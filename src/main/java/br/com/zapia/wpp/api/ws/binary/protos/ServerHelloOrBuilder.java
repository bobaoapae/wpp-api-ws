// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

public interface ServerHelloOrBuilder extends
    // @@protoc_insertion_point(interface_extends:binary.ServerHello)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>optional bytes ephemeral = 1;</code>
   * @return Whether the ephemeral field is set.
   */
  boolean hasEphemeral();
  /**
   * <code>optional bytes ephemeral = 1;</code>
   * @return The ephemeral.
   */
  com.google.protobuf.ByteString getEphemeral();

  /**
   * <code>optional bytes static = 2;</code>
   * @return Whether the static field is set.
   */
  boolean hasStatic();
  /**
   * <code>optional bytes static = 2;</code>
   * @return The static.
   */
  com.google.protobuf.ByteString getStatic();

  /**
   * <code>optional bytes payload = 3;</code>
   * @return Whether the payload field is set.
   */
  boolean hasPayload();
  /**
   * <code>optional bytes payload = 3;</code>
   * @return The payload.
   */
  com.google.protobuf.ByteString getPayload();
}
