// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

public interface ButtonOrBuilder extends
    // @@protoc_insertion_point(interface_extends:binary.Button)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>optional string buttonId = 1;</code>
   * @return Whether the buttonId field is set.
   */
  boolean hasButtonId();
  /**
   * <code>optional string buttonId = 1;</code>
   * @return The buttonId.
   */
  java.lang.String getButtonId();
  /**
   * <code>optional string buttonId = 1;</code>
   * @return The bytes for buttonId.
   */
  com.google.protobuf.ByteString
      getButtonIdBytes();

  /**
   * <code>optional .binary.ButtonText buttonText = 2;</code>
   * @return Whether the buttonText field is set.
   */
  boolean hasButtonText();
  /**
   * <code>optional .binary.ButtonText buttonText = 2;</code>
   * @return The buttonText.
   */
  br.com.zapia.wpp.api.ws.binary.protos.ButtonText getButtonText();
  /**
   * <code>optional .binary.ButtonText buttonText = 2;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.ButtonTextOrBuilder getButtonTextOrBuilder();

  /**
   * <code>optional .binary.Button.ButtonType type = 3;</code>
   * @return Whether the type field is set.
   */
  boolean hasType();
  /**
   * <code>optional .binary.Button.ButtonType type = 3;</code>
   * @return The type.
   */
  br.com.zapia.wpp.api.ws.binary.protos.Button.ButtonType getType();

  /**
   * <code>optional .binary.NativeFlowInfo nativeFlowInfo = 4;</code>
   * @return Whether the nativeFlowInfo field is set.
   */
  boolean hasNativeFlowInfo();
  /**
   * <code>optional .binary.NativeFlowInfo nativeFlowInfo = 4;</code>
   * @return The nativeFlowInfo.
   */
  br.com.zapia.wpp.api.ws.binary.protos.NativeFlowInfo getNativeFlowInfo();
  /**
   * <code>optional .binary.NativeFlowInfo nativeFlowInfo = 4;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.NativeFlowInfoOrBuilder getNativeFlowInfoOrBuilder();
}
