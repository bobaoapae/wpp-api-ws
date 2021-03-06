// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

public interface AppStateSyncKeyFingerprintOrBuilder extends
    // @@protoc_insertion_point(interface_extends:binary.AppStateSyncKeyFingerprint)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>optional uint32 rawId = 1;</code>
   * @return Whether the rawId field is set.
   */
  boolean hasRawId();
  /**
   * <code>optional uint32 rawId = 1;</code>
   * @return The rawId.
   */
  int getRawId();

  /**
   * <code>optional uint32 currentIndex = 2;</code>
   * @return Whether the currentIndex field is set.
   */
  boolean hasCurrentIndex();
  /**
   * <code>optional uint32 currentIndex = 2;</code>
   * @return The currentIndex.
   */
  int getCurrentIndex();

  /**
   * <code>repeated uint32 deviceIndexes = 3 [packed = true];</code>
   * @return A list containing the deviceIndexes.
   */
  java.util.List<java.lang.Integer> getDeviceIndexesList();
  /**
   * <code>repeated uint32 deviceIndexes = 3 [packed = true];</code>
   * @return The count of deviceIndexes.
   */
  int getDeviceIndexesCount();
  /**
   * <code>repeated uint32 deviceIndexes = 3 [packed = true];</code>
   * @param index The index of the element to return.
   * @return The deviceIndexes at the given index.
   */
  int getDeviceIndexes(int index);
}
