// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

public interface NotificationMessageInfoOrBuilder extends
    // @@protoc_insertion_point(interface_extends:binary.NotificationMessageInfo)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>optional .binary.MessageKey key = 1;</code>
   * @return Whether the key field is set.
   */
  boolean hasKey();
  /**
   * <code>optional .binary.MessageKey key = 1;</code>
   * @return The key.
   */
  br.com.zapia.wpp.api.ws.binary.protos.MessageKey getKey();
  /**
   * <code>optional .binary.MessageKey key = 1;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.MessageKeyOrBuilder getKeyOrBuilder();

  /**
   * <code>optional .binary.Message message = 2;</code>
   * @return Whether the message field is set.
   */
  boolean hasMessage();
  /**
   * <code>optional .binary.Message message = 2;</code>
   * @return The message.
   */
  br.com.zapia.wpp.api.ws.binary.protos.Message getMessage();
  /**
   * <code>optional .binary.Message message = 2;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.MessageOrBuilder getMessageOrBuilder();

  /**
   * <code>optional uint64 messageTimestamp = 3;</code>
   * @return Whether the messageTimestamp field is set.
   */
  boolean hasMessageTimestamp();
  /**
   * <code>optional uint64 messageTimestamp = 3;</code>
   * @return The messageTimestamp.
   */
  long getMessageTimestamp();

  /**
   * <code>optional string participant = 4;</code>
   * @return Whether the participant field is set.
   */
  boolean hasParticipant();
  /**
   * <code>optional string participant = 4;</code>
   * @return The participant.
   */
  java.lang.String getParticipant();
  /**
   * <code>optional string participant = 4;</code>
   * @return The bytes for participant.
   */
  com.google.protobuf.ByteString
      getParticipantBytes();
}
