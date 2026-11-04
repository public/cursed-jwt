// Stand-in for Envoy's source/common/protobuf/protobuf.h: Envoy's JWT library only needs the Protobuf namespace
// alias, Struct / Value and the JSON utilities.
#pragma once
#include "google/protobuf/struct.pb.h"
#include "google/protobuf/util/json_util.h"

namespace Envoy {
namespace Protobuf = ::google::protobuf;
} // namespace Envoy
