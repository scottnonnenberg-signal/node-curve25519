#include <string.h>
#include <stdlib.h>
#ifdef _WIN32
  #include <io.h>
#else
  #include <unistd.h>
#endif

#include "native/curve25519-donna.h"
#include "native/ed25519/additions/curve_sigs.h"

#include <nan.h>

static NAN_METHOD(DoDonna) {
  Nan::HandleScope scope;
  const char *usage = "usage: donna(a, b, c)";
  if (info.Length() != 3) {
    return Nan::ThrowSyntaxError(usage);
  }
  unsigned char* arg0 = (unsigned char*) node::Buffer::Data(info[0]->ToObject(info.GetIsolate()->GetCurrentContext()).ToLocalChecked());
  unsigned char* arg1 = (unsigned char*) node::Buffer::Data(info[1]->ToObject(info.GetIsolate()->GetCurrentContext()).ToLocalChecked());
  unsigned char* arg2 = (unsigned char*) node::Buffer::Data(info[2]->ToObject(info.GetIsolate()->GetCurrentContext()).ToLocalChecked());

  int result = curve25519_donna(arg0, arg1, arg2);

  info.GetReturnValue().Set(result);
}

static NAN_METHOD(DoSign) {
  Nan::HandleScope scope;
  const char *usage = "usage: sign(a, b, c, d)";
  if (info.Length() != 4) {
    return Nan::ThrowSyntaxError(usage);
  }
  unsigned char* arg0 = (unsigned char*) node::Buffer::Data(info[0]->ToObject(info.GetIsolate()->GetCurrentContext()).ToLocalChecked());
  unsigned char* arg1 = (unsigned char*) node::Buffer::Data(info[1]->ToObject(info.GetIsolate()->GetCurrentContext()).ToLocalChecked());
  unsigned char* arg2 = (unsigned char*) node::Buffer::Data(info[2]->ToObject(info.GetIsolate()->GetCurrentContext()).ToLocalChecked());
  unsigned long arg3 = (unsigned long) info[3]->ToInt32(info.GetIsolate()->GetCurrentContext()).ToLocalChecked()->Value();

  curve25519_sign(arg0, arg1, arg2, arg3);
}

static NAN_METHOD(DoVerify) {
  Nan::HandleScope scope;
  const char *usage = "usage: verify(a, b, c, d)";
  if (info.Length() != 4) {
    return Nan::ThrowSyntaxError(usage);
  }
  unsigned char* arg0 = (unsigned char*) node::Buffer::Data(info[0]->ToObject(info.GetIsolate()->GetCurrentContext()).ToLocalChecked());
  unsigned char* arg1 = (unsigned char*) node::Buffer::Data(info[1]->ToObject(info.GetIsolate()->GetCurrentContext()).ToLocalChecked());
  unsigned char* arg2 = (unsigned char*) node::Buffer::Data(info[2]->ToObject(info.GetIsolate()->GetCurrentContext()).ToLocalChecked());
  unsigned long arg3 = (unsigned long) info[3]->ToInt32(info.GetIsolate()->GetCurrentContext()).ToLocalChecked()->Value();

  int result = curve25519_verify(arg0, arg1, arg2, arg3);

  info.GetReturnValue().Set(result);
}

extern "C" NAN_MODULE_INIT(init) {
  Nan::HandleScope scope;
  Nan::SetMethod(target, "donna", DoDonna);
  Nan::SetMethod(target, "sign", DoSign);
  Nan::SetMethod(target, "verify", DoVerify);
}


NODE_MODULE(NODE_GYP_MODULE_NAME, init)
