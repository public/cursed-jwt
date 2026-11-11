/* _native.c — the CPython binding of cursed-crypto (crypto/include/cursed_crypto.h) behind cursed_crypto/__init__.py.
 * Part of cursed-jwt, MIT licence (see LICENSE).
 *
 *   PKey          a cc_pkey_t (Ed25519, ES256 or RS256), built once and owned by the object
 *     pkey_ed25519(pub32) / pkey_es256(x32, y32) / pkey_rs256(n, e)   -> PKey, or None where cc_pkey_* refuses
 *     .verify(sig, data, der)        -> True / False / None (None: not handled here, the caller asks pyca)
 *     .verify_batch(sigs, datas, der) -> (list of True / False / None, number of Nones)
 *   HMACKey(key)  the two SHA-256 midstates of an HMAC-SHA256 key (cc_hmac_key_t); the raw key is not kept
 *     .verify(data, tag) / .verify_batch(datas, tags)   as above; tags are compared by cc_hmac_sha256_verify only
 *     .digest(data) / .digest_batch(datas)              32-byte MACs
 *   sha256_batch(datas), der_to_raw(sig), engine(), cpu_features()
 *
 * der: ES256 signatures are DER (as pyca/cryptography takes them) and are converted here to r || s by a strict
 * parser that accepts only what OpenSSL's ECDSA_verify accepts (d2i, then re-encode and compare: DER only, no
 * trailing bytes) for the integers OpenSSL would go on to range-check; cc_verify_batch then checks 1 <= r, s < n.
 *
 * Buffers: every item must export a C-contiguous buffer (bytes, bytearray, memoryview, ...); the first one that
 * doesn't raises TypeError / BufferError before anything is verified, as pyca would on that item.  All Py_buffers
 * of a call are acquired first, then the GIL is released for the crypto (no Python object is touched while it is
 * released; an exported bytearray can't be resized), then it is taken back and the buffers released.
 * Items longer than INT_MAX (the cc_ API takes int lengths) come back as None, for pyca. */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <limits.h>
#include <string.h>

#include "cursed_crypto.h"

#define CHUNK 256 /* items per cc_ call: the scratch arrays stay ~30 KB (heap, no mmap), and n fits in int */

/* ---------------------------------------------------------------------------------- DER -> r || s */
/* One INTEGER of an ECDSA-Sig-Value, DER, positive, at most 32 bytes of magnitude, right-aligned into out[32].
 * Returns the bytes consumed, or 0.  Rejects: wrong tag, long-form or zero length, a length past the end, a negative
 * value (top bit set), a non-minimal encoding (a 00 not needed to clear the top bit), a magnitude over 32 bytes.
 * Zero (02 01 00) is passed through as 0: cc_verify_batch rejects it, as OpenSSL's range check does. */
static size_t der_int(const uint8_t *p, size_t n, uint8_t out[32]) {
    if (n < 3 || p[0] != 0x02) return 0;
    size_t l = p[1];
    if (l == 0 || l >= 0x80 || l > n - 2) return 0;
    const uint8_t *v = p + 2;
    if (v[0] & 0x80) return 0;                          /* negative */
    if (v[0] == 0 && l > 1 && !(v[1] & 0x80)) return 0; /* non-minimal */
    const uint8_t *m = v;
    size_t ml = l;
    if (m[0] == 0 && ml > 1) m++, ml--;
    if (ml > 32) return 0;
    memset(out, 0, 32);
    memcpy(out + 32 - ml, m, ml);
    return 2 + l;
}
/* SEQUENCE { INTEGER r, INTEGER s } in DER with nothing after it -> r || s.  1 on success.  The SEQUENCE of two
 * INTEGERs of at most 33 content bytes each is at most 70 bytes, so its length is always short form; a long form
 * there, or anything this function rejects, is either non-DER or holds an integer OpenSSL's range check rejects. */
static int der_to_raw64(const uint8_t *d, size_t n, uint8_t out[64]) {
    if (n < 8 || n > 72 || d[0] != 0x30 || d[1] != n - 2) return 0;
    size_t a = der_int(d + 2, n - 2, out);
    if (!a) return 0;
    size_t b = der_int(d + 2 + a, n - 2 - a, out + 32);
    return b && 2 + a + b == n;
}

/* ---------------------------------------------------------------------------------- buffers */
typedef struct {
    Py_ssize_t n;
    Py_buffer *buf; /* n per list, list-major */
    int nl;         /* lists */
    Py_ssize_t got; /* buffers acquired */
    PyObject *seq[2];
} bufs_t;

static void bufs_free(bufs_t *b) {
    for (Py_ssize_t i = 0; i < b->got; i++) PyBuffer_Release(&b->buf[i]);
    PyMem_Free(b->buf);
    for (int j = 0; j < b->nl; j++) Py_XDECREF(b->seq[j]);
    b->buf = NULL, b->got = 0;
}

static int get_buf(PyObject *o, Py_buffer *v) {
    if (PyObject_GetBuffer(o, v, PyBUF_SIMPLE) < 0) {
        if (PyErr_ExceptionMatches(PyExc_TypeError)) {
            PyErr_Clear();
            PyErr_Format(PyExc_TypeError, "a bytes-like object is required, not '%.100s'", Py_TYPE(o)->tp_name);
        }
        return -1;
    }
    return 0;
}

/* Acquire the buffers of nl iterables of equal length. */
static int bufs_get(bufs_t *b, int nl, PyObject *const *lists, const char *const *names) {
    memset(b, 0, sizeof *b);
    b->nl = nl;
    for (int j = 0; j < nl; j++) {
        b->seq[j] = PySequence_Fast(lists[j], "expected an iterable of bytes-like objects");
        if (!b->seq[j]) {
            b->nl = j;
            bufs_free(b);
            return -1;
        }
    }
    b->n = PySequence_Fast_GET_SIZE(b->seq[0]);
    for (int j = 1; j < nl; j++)
        if (PySequence_Fast_GET_SIZE(b->seq[j]) != b->n) {
            PyErr_Format(PyExc_ValueError, "%s and %s have different lengths (%zd and %zd)", names[0], names[j], b->n,
                         PySequence_Fast_GET_SIZE(b->seq[j]));
            bufs_free(b);
            return -1;
        }
    if (b->n > PY_SSIZE_T_MAX / (Py_ssize_t)sizeof(Py_buffer) / nl) {
        PyErr_NoMemory();
        bufs_free(b);
        return -1;
    }
    b->buf = PyMem_Malloc(sizeof(Py_buffer) * (size_t)(b->n * nl) + 1);
    if (!b->buf) {
        PyErr_NoMemory();
        bufs_free(b);
        return -1;
    }
    /* item-major acquisition order, so the first bad item (in either list) is the one reported, as pyca's loop would */
    for (Py_ssize_t i = 0; i < b->n; i++)
        for (int j = 0; j < nl; j++) {
            if (get_buf(PySequence_Fast_GET_ITEM(b->seq[j], i), &b->buf[j * b->n + i]) < 0) {
                /* release the ones taken so far: they are not contiguous in buf, so release by hand */
                for (Py_ssize_t k = 0; k <= i; k++)
                    for (int jj = 0; jj < nl; jj++)
                        if (k < i || jj < j) PyBuffer_Release(&b->buf[jj * b->n + k]);
                b->got = 0;
                bufs_free(b);
                return -1;
            }
        }
    b->got = b->n * nl; /* buf[0 .. n*nl) are all acquired */
    return 0;
}
#define BUF(b, j, i) (&(b)->buf[(Py_ssize_t)(j) * (b)->n + (i)])

/* scratch arrays for one chunk */
typedef struct {
    const uint8_t *msg[CHUNK], *sig[CHUNK];
    int len[CHUNK], slen[CHUNK];
    uint8_t ok[CHUNK], skip[CHUNK];
    uint8_t raw[CHUNK][64];
    uint8_t mac[CHUNK][32];
} scratch_t;

static scratch_t *scratch_new(void) {
    scratch_t *s = PyMem_RawMalloc(sizeof *s);
    if (!s) PyErr_NoMemory();
    return s;
}

/* list of True / False / None from ok[] / skip[] */
static PyObject *verdicts(Py_ssize_t n, const uint8_t *ok, const uint8_t *skip, Py_ssize_t *nskip) {
    PyObject *l = PyList_New(n);
    if (!l) return NULL;
    Py_ssize_t k = 0;
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject *v = skip[i] ? (k++, Py_None) : ok[i] ? Py_True : Py_False;
        Py_INCREF(v);
        PyList_SET_ITEM(l, i, v);
    }
    *nskip = k;
    return l;
}

/* ---------------------------------------------------------------------------------- PKey */
typedef struct {
    PyObject_HEAD cc_pkey_t *k;
    int alg, sbytes;
} PKeyObject;

static void pkey_dealloc(PKeyObject *self) {
    cc_pkey_free(self->k);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyTypeObject PKeyType;

static PyObject *pkey_wrap(cc_pkey_t *k) {
    if (!k) Py_RETURN_NONE;
    PKeyObject *o = PyObject_New(PKeyObject, &PKeyType);
    if (!o) {
        cc_pkey_free(k);
        return NULL;
    }
    o->k = k, o->alg = cc_pkey_alg(k), o->sbytes = cc_pkey_sig_bytes(k);
    return (PyObject *)o;
}

/* Fill one chunk's pointers: items [base, base+m) of b (list 0 signatures, list 1 messages). */
static void pk_fill(const PKeyObject *self, const bufs_t *b, Py_ssize_t base, int m, int der, scratch_t *s) {
    for (int i = 0; i < m; i++) {
        const Py_buffer *sg = BUF(b, 0, base + i), *ms = BUF(b, 1, base + i);
        s->skip[i] = 0;
        if (ms->len > INT_MAX) { /* for pyca */
            s->skip[i] = 1, s->msg[i] = NULL, s->len[i] = 0, s->sig[i] = NULL, s->slen[i] = 0;
            continue;
        }
        s->msg[i] = ms->buf, s->len[i] = (int)ms->len;
        if (der) {
            int okd = der_to_raw64(sg->buf, (size_t)sg->len, s->raw[i]);
            s->sig[i] = s->raw[i], s->slen[i] = okd ? 64 : 0; /* slen 0: rejected without hashing */
        } else {
            s->sig[i] = sg->buf;
            s->slen[i] = sg->len == self->sbytes ? self->sbytes : 0;
        }
    }
}

static PyObject *pkey_verify_batch(PKeyObject *self, PyObject *args) {
    PyObject *lists[2];
    int der = 0;
    if (!PyArg_ParseTuple(args, "OO|p", &lists[0], &lists[1], &der)) return NULL;
    der = der && self->alg == CC_PK_ES256;
    static const char *const names[2] = { "signatures", "datas" };
    bufs_t b;
    if (bufs_get(&b, 2, lists, names) < 0) return NULL;
    scratch_t *s = scratch_new();
    uint8_t *ok = PyMem_Malloc((size_t)b.n * 2 + 1);
    if (!s || !ok) {
        PyMem_RawFree(s), PyMem_Free(ok), bufs_free(&b);
        return s ? PyErr_NoMemory() : NULL;
    }
    uint8_t *skip = ok + b.n;
    Py_BEGIN_ALLOW_THREADS;
    for (Py_ssize_t base = 0; base < b.n; base += CHUNK) {
        int m = (int)(b.n - base < CHUNK ? b.n - base : CHUNK);
        pk_fill(self, &b, base, m, der, s);
        cc_verify_batch(self->k, m, s->msg, s->len, s->sig, s->slen, s->ok);
        for (int i = 0; i < m; i++) ok[base + i] = s->ok[i] & !s->skip[i], skip[base + i] = s->skip[i];
    }
    Py_END_ALLOW_THREADS;
    bufs_free(&b);
    PyMem_RawFree(s);
    Py_ssize_t ns = 0;
    PyObject *l = verdicts(b.n, ok, skip, &ns);
    PyMem_Free(ok);
    if (!l) return NULL;
    return Py_BuildValue("Nn", l, ns);
}

static PyObject *pkey_verify(PKeyObject *self, PyObject *args) {
    Py_buffer sg, ms;
    int der = 0;
    if (!PyArg_ParseTuple(args, "y*y*|p", &sg, &ms, &der)) return NULL;
    der = der && self->alg == CC_PK_ES256;
    if (ms.len > INT_MAX) {
        PyBuffer_Release(&sg), PyBuffer_Release(&ms);
        Py_RETURN_NONE;
    }
    uint8_t raw[64], ok = 0;
    const uint8_t *mp = ms.buf, *sp = sg.buf;
    int ml = (int)ms.len, sl = sg.len == self->sbytes ? self->sbytes : 0;
    Py_BEGIN_ALLOW_THREADS;
    if (der) sp = raw, sl = der_to_raw64(sg.buf, (size_t)sg.len, raw) ? 64 : 0;
    cc_verify_batch(self->k, 1, &mp, &ml, &sp, &sl, &ok);
    Py_END_ALLOW_THREADS;
    PyBuffer_Release(&sg), PyBuffer_Release(&ms);
    return PyBool_FromLong(ok);
}

static PyObject *pkey_get_alg(PKeyObject *self, void *c) { return PyLong_FromLong(self->alg); }
static PyObject *pkey_get_sbytes(PKeyObject *self, void *c) { return PyLong_FromLong(self->sbytes); }

static PyMethodDef pkey_methods[] = { { "verify", (PyCFunction)pkey_verify, METH_VARARGS,
                                        "verify(sig, data, der=False) -> bool | None" },
                                      { "verify_batch", (PyCFunction)pkey_verify_batch, METH_VARARGS,
                                        "verify_batch(sigs, datas, der=False) -> (list[bool | None], number of None)" },
                                      { NULL } };
static PyGetSetDef pkey_getset[] = { { "alg", (getter)pkey_get_alg, NULL, "CC_PK_*", NULL },
                                     { "sig_bytes", (getter)pkey_get_sbytes, NULL, "raw signature length", NULL },
                                     { NULL } };
static PyTypeObject PKeyType = {
    .ob_base = { PyObject_HEAD_INIT(NULL) 0 },
    .tp_name = "cursed_crypto._native.PKey",
    .tp_basicsize = sizeof(PKeyObject),
    .tp_dealloc = (destructor)pkey_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "a cursed-crypto public key (cc_pkey_t); built by pkey_ed25519 / pkey_es256 / pkey_rs256",
    .tp_methods = pkey_methods,
    .tp_getset = pkey_getset,
};

static PyObject *m_pkey_ed25519(PyObject *m, PyObject *args) {
    Py_buffer p;
    if (!PyArg_ParseTuple(args, "y*", &p)) return NULL;
    cc_pkey_t *k = NULL;
    if (p.len == 32) {
        Py_BEGIN_ALLOW_THREADS;
        k = cc_pkey_ed25519(p.buf);
        Py_END_ALLOW_THREADS;
    }
    PyBuffer_Release(&p);
    return pkey_wrap(k);
}
static PyObject *m_pkey_es256(PyObject *m, PyObject *args) {
    Py_buffer x, y;
    if (!PyArg_ParseTuple(args, "y*y*", &x, &y)) return NULL;
    cc_pkey_t *k = NULL;
    if (x.len == 32 && y.len == 32) {
        Py_BEGIN_ALLOW_THREADS;
        k = cc_pkey_es256(x.buf, y.buf);
        Py_END_ALLOW_THREADS;
    }
    PyBuffer_Release(&x), PyBuffer_Release(&y);
    return pkey_wrap(k);
}
static PyObject *m_pkey_rs256(PyObject *m, PyObject *args) {
    Py_buffer n, e;
    if (!PyArg_ParseTuple(args, "y*y*", &n, &e)) return NULL;
    cc_pkey_t *k;
    Py_BEGIN_ALLOW_THREADS;
    k = cc_pkey_rs256(n.buf, (size_t)n.len, e.buf, (size_t)e.len);
    Py_END_ALLOW_THREADS;
    PyBuffer_Release(&n), PyBuffer_Release(&e);
    return pkey_wrap(k);
}

/* ---------------------------------------------------------------------------------- HMAC-SHA256 */
typedef struct {
    PyObject_HEAD cc_hmac_key_t k;
} HMACKeyObject;

static int hmac_init(HMACKeyObject *self, PyObject *args, PyObject *kw) {
    Py_buffer key;
    static char *kwl[] = { "key", NULL };
    if (!PyArg_ParseTupleAndKeywords(args, kw, "y*", kwl, &key)) return -1;
    cc_hmac_key_init(&self->k, key.buf, (size_t)key.len);
    PyBuffer_Release(&key);
    return 0;
}
static void hmac_dealloc(HMACKeyObject *self) {
    /* the midstates are key material: clear them (volatile, so the store isn't dropped) */
    volatile uint8_t *p = (volatile uint8_t *)&self->k;
    for (size_t i = 0; i < sizeof self->k; i++) p[i] = 0;
    Py_TYPE(self)->tp_free((PyObject *)self);
}

/* Small single HMACs keep the GIL: releasing and retaking it costs as much as the MAC. */
#define GIL_MIN 2048

static PyObject *hmac_verify_batch(HMACKeyObject *self, PyObject *args) {
    PyObject *lists[2];
    if (!PyArg_ParseTuple(args, "OO", &lists[0], &lists[1])) return NULL;
    static const char *const names[2] = { "datas", "tags" };
    bufs_t b;
    if (bufs_get(&b, 2, lists, names) < 0) return NULL;
    scratch_t *s = scratch_new();
    uint8_t *ok = PyMem_Malloc((size_t)b.n * 2 + 1);
    if (!s || !ok) {
        PyMem_RawFree(s), PyMem_Free(ok), bufs_free(&b);
        return s ? PyErr_NoMemory() : NULL;
    }
    uint8_t *skip = ok + b.n;
    Py_BEGIN_ALLOW_THREADS;
    for (Py_ssize_t base = 0; base < b.n; base += CHUNK) {
        int m = (int)(b.n - base < CHUNK ? b.n - base : CHUNK), c = 0, at[CHUNK];
        for (int i = 0; i < m; i++) {
            const Py_buffer *ms = BUF(&b, 0, base + i), *tg = BUF(&b, 1, base + i);
            /* not 32 bytes (a truncated tag) or too long for int: for pyca */
            skip[base + i] = tg->len != 32 || ms->len > INT_MAX;
            ok[base + i] = 0;
            if (skip[base + i]) continue;
            s->msg[c] = ms->buf, s->len[c] = (int)ms->len;
            memcpy(s->mac[c], tg->buf, 32); /* cc_hmac_sha256_verify takes the tags packed */
            at[c++] = i;
        }
        cc_hmac_sha256_verify(&self->k, c, s->msg, s->len, (const uint8_t(*)[32])s->mac, s->ok);
        for (int j = 0; j < c; j++) ok[base + at[j]] = s->ok[j];
    }
    Py_END_ALLOW_THREADS;
    bufs_free(&b);
    PyMem_RawFree(s);
    Py_ssize_t ns = 0;
    PyObject *l = verdicts(b.n, ok, skip, &ns);
    PyMem_Free(ok);
    if (!l) return NULL;
    return Py_BuildValue("Nn", l, ns);
}

static PyObject *hmac_verify(HMACKeyObject *self, PyObject *args) {
    Py_buffer ms, tg;
    if (!PyArg_ParseTuple(args, "y*y*", &ms, &tg)) return NULL;
    if (tg.len != 32 || ms.len > INT_MAX) {
        PyBuffer_Release(&ms), PyBuffer_Release(&tg);
        Py_RETURN_NONE;
    }
    const uint8_t *mp = ms.buf;
    int ml = (int)ms.len;
    uint8_t ok = 0;
    if (ms.len >= GIL_MIN) {
        Py_BEGIN_ALLOW_THREADS;
        cc_hmac_sha256_verify(&self->k, 1, &mp, &ml, (const uint8_t(*)[32])tg.buf, &ok);
        Py_END_ALLOW_THREADS;
    } else {
        cc_hmac_sha256_verify(&self->k, 1, &mp, &ml, (const uint8_t(*)[32])tg.buf, &ok);
    }
    PyBuffer_Release(&ms), PyBuffer_Release(&tg);
    return PyBool_FromLong(ok);
}

/* MACs (key != NULL) or SHA-256 digests (key == NULL) of an iterable, as a list of 32-byte bytes */
static PyObject *digests(const cc_hmac_key_t *key, PyObject *datas) {
    static const char *const names[1] = { "datas" };
    bufs_t b;
    if (bufs_get(&b, 1, &datas, names) < 0) return NULL;
    for (Py_ssize_t i = 0; i < b.n; i++)
        if (BUF(&b, 0, i)->len > INT_MAX) {
            bufs_free(&b);
            return PyErr_Format(PyExc_OverflowError, "data item %zd is longer than %d bytes", i, INT_MAX);
        }
    scratch_t *s = scratch_new();
    uint8_t(*out)[32] = PyMem_Malloc((size_t)b.n * 32 + 1);
    if (!s || !out) {
        PyMem_RawFree(s), PyMem_Free(out), bufs_free(&b);
        return s ? PyErr_NoMemory() : NULL;
    }
    Py_BEGIN_ALLOW_THREADS;
    for (Py_ssize_t base = 0; base < b.n; base += CHUNK) {
        int m = (int)(b.n - base < CHUNK ? b.n - base : CHUNK);
        for (int i = 0; i < m; i++) s->msg[i] = BUF(&b, 0, base + i)->buf, s->len[i] = (int)BUF(&b, 0, base + i)->len;
        if (key) cc_hmac_sha256_bytes(key, m, s->msg, s->len, out + base);
        else cc_sha256_bytes(m, s->msg, s->len, out + base);
    }
    Py_END_ALLOW_THREADS;
    bufs_free(&b);
    PyMem_RawFree(s);
    PyObject *l = PyList_New(b.n);
    for (Py_ssize_t i = 0; l && i < b.n; i++) {
        PyObject *d = PyBytes_FromStringAndSize((const char *)out[i], 32);
        if (!d) Py_CLEAR(l);
        else PyList_SET_ITEM(l, i, d);
    }
    PyMem_Free(out);
    return l;
}

static PyObject *hmac_digest_batch(HMACKeyObject *self, PyObject *datas) { return digests(&self->k, datas); }

static PyObject *hmac_digest(HMACKeyObject *self, PyObject *arg) {
    Py_buffer ms;
    if (get_buf(arg, &ms) < 0) return NULL;
    if (ms.len > INT_MAX) {
        PyBuffer_Release(&ms);
        return PyErr_Format(PyExc_OverflowError, "data is longer than %d bytes", INT_MAX);
    }
    const uint8_t *mp = ms.buf;
    int ml = (int)ms.len;
    uint8_t mac[32];
    if (ms.len >= GIL_MIN) {
        Py_BEGIN_ALLOW_THREADS;
        cc_hmac_sha256_bytes(&self->k, 1, &mp, &ml, &mac);
        Py_END_ALLOW_THREADS;
    } else {
        cc_hmac_sha256_bytes(&self->k, 1, &mp, &ml, &mac);
    }
    PyBuffer_Release(&ms);
    return PyBytes_FromStringAndSize((const char *)mac, 32);
}

static PyMethodDef hmac_methods[] = {
    { "verify", (PyCFunction)hmac_verify, METH_VARARGS, "verify(data, tag) -> bool | None" },
    { "verify_batch", (PyCFunction)hmac_verify_batch, METH_VARARGS,
      "verify_batch(datas, tags) -> (list[bool | None], number of None)" },
    { "digest", (PyCFunction)hmac_digest, METH_O, "digest(data) -> bytes" },
    { "digest_batch", (PyCFunction)hmac_digest_batch, METH_O, "digest_batch(datas) -> list[bytes]" },
    { NULL }
};
static PyTypeObject HMACKeyType = {
    .ob_base = { PyObject_HEAD_INIT(NULL) 0 },
    .tp_name = "cursed_crypto._native.HMACKey",
    .tp_basicsize = sizeof(HMACKeyObject),
    .tp_dealloc = (destructor)hmac_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_doc = "HMACKey(key): an HMAC-SHA256 key's midstates (cc_hmac_key_t)",
    .tp_methods = hmac_methods,
    .tp_init = (initproc)hmac_init,
    .tp_new = PyType_GenericNew,
};

/* ---------------------------------------------------------------------------------- module */
static PyObject *m_sha256_batch(PyObject *m, PyObject *datas) { return digests(NULL, datas); }

static PyObject *m_der_to_raw(PyObject *m, PyObject *args) {
    Py_buffer d;
    if (!PyArg_ParseTuple(args, "y*", &d)) return NULL;
    uint8_t raw[64];
    int ok = der_to_raw64(d.buf, (size_t)d.len, raw);
    PyBuffer_Release(&d);
    if (!ok) Py_RETURN_NONE;
    return PyBytes_FromStringAndSize((const char *)raw, 64);
}
/* The binding's own cost, for benchmarks: everything verify_batch does (iterables to C arrays, buffers acquired and
 * released, the GIL released and taken back, the result list) except the crypto. */
static PyObject *m_overhead(PyObject *m, PyObject *args) {
    PyObject *lists[2];
    if (!PyArg_ParseTuple(args, "OO", &lists[0], &lists[1])) return NULL;
    static const char *const names[2] = { "signatures", "datas" };
    bufs_t b;
    if (bufs_get(&b, 2, lists, names) < 0) return NULL;
    scratch_t *s = scratch_new();
    uint8_t *ok = PyMem_Malloc((size_t)b.n * 2 + 1);
    if (!s || !ok) {
        PyMem_RawFree(s), PyMem_Free(ok), bufs_free(&b);
        return s ? PyErr_NoMemory() : NULL;
    }
    memset(ok, 0, (size_t)b.n * 2);
    Py_BEGIN_ALLOW_THREADS;
    for (Py_ssize_t base = 0; base < b.n; base += CHUNK) {
        int mm = (int)(b.n - base < CHUNK ? b.n - base : CHUNK);
        for (int i = 0; i < mm; i++)
            s->msg[i] = BUF(&b, 1, base + i)->buf, s->len[i] = (int)BUF(&b, 1, base + i)->len,
            s->sig[i] = BUF(&b, 0, base + i)->buf;
    }
    Py_END_ALLOW_THREADS;
    bufs_free(&b);
    PyMem_RawFree(s);
    Py_ssize_t ns = 0;
    PyObject *l = verdicts(b.n, ok, ok + b.n, &ns);
    PyMem_Free(ok);
    if (!l) return NULL;
    return Py_BuildValue("Nn", l, ns);
}
static PyObject *m_engine(PyObject *m, PyObject *unused) { return PyUnicode_FromString(cc_engine()); }
static PyObject *m_cpu_features(PyObject *m, PyObject *unused) { return PyLong_FromUnsignedLong(cc_cpu_features()); }

static PyMethodDef module_methods[] = {
    { "pkey_ed25519", m_pkey_ed25519, METH_VARARGS, "pkey_ed25519(pub32) -> PKey | None" },
    { "pkey_es256", m_pkey_es256, METH_VARARGS, "pkey_es256(x32, y32) -> PKey | None" },
    { "pkey_rs256", m_pkey_rs256, METH_VARARGS, "pkey_rs256(n, e) -> PKey | None (big-endian)" },
    { "sha256_batch", m_sha256_batch, METH_O, "sha256_batch(datas) -> list[bytes]" },
    { "der_to_raw", m_der_to_raw, METH_VARARGS, "der_to_raw(sig) -> r || s (64 bytes) | None" },
    { "_overhead", m_overhead, METH_VARARGS, "verify_batch's binding work without the crypto (benchmarks)" },
    { "engine", m_engine, METH_NOARGS, "the HMAC-SHA256 engine cc_hmac_sha256_batch uses on this CPU" },
    { "cpu_features", m_cpu_features, METH_NOARGS, "cc_cpu_features(): CC_CPU_* bits" },
    { NULL }
};
static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT, "cursed_crypto._native", "cursed-crypto's C binding (see cursed_crypto)", -1, module_methods,
};

PyMODINIT_FUNC PyInit__native(void) {
    if (PyType_Ready(&PKeyType) < 0 || PyType_Ready(&HMACKeyType) < 0) return NULL;
    PyObject *m = PyModule_Create(&module_def);
    if (!m) return NULL;
    Py_INCREF(&HMACKeyType);
    Py_INCREF(&PKeyType);
    if (PyModule_AddObject(m, "HMACKey", (PyObject *)&HMACKeyType) < 0 ||
        PyModule_AddObject(m, "PKey", (PyObject *)&PKeyType) < 0 ||
        PyModule_AddIntConstant(m, "PK_RS256", CC_PK_RS256) || PyModule_AddIntConstant(m, "PK_ES256", CC_PK_ES256) ||
        PyModule_AddIntConstant(m, "PK_ED25519", CC_PK_ED25519)) {
        Py_DECREF(m);
        return NULL;
    }
    return m;
}
