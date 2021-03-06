// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

public interface ProductListInfoOrBuilder extends
    // @@protoc_insertion_point(interface_extends:binary.ProductListInfo)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>repeated .binary.ProductSection productSections = 1;</code>
   */
  java.util.List<br.com.zapia.wpp.api.ws.binary.protos.ProductSection> 
      getProductSectionsList();
  /**
   * <code>repeated .binary.ProductSection productSections = 1;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.ProductSection getProductSections(int index);
  /**
   * <code>repeated .binary.ProductSection productSections = 1;</code>
   */
  int getProductSectionsCount();
  /**
   * <code>repeated .binary.ProductSection productSections = 1;</code>
   */
  java.util.List<? extends br.com.zapia.wpp.api.ws.binary.protos.ProductSectionOrBuilder> 
      getProductSectionsOrBuilderList();
  /**
   * <code>repeated .binary.ProductSection productSections = 1;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.ProductSectionOrBuilder getProductSectionsOrBuilder(
      int index);

  /**
   * <code>optional .binary.ProductListHeaderImage headerImage = 2;</code>
   * @return Whether the headerImage field is set.
   */
  boolean hasHeaderImage();
  /**
   * <code>optional .binary.ProductListHeaderImage headerImage = 2;</code>
   * @return The headerImage.
   */
  br.com.zapia.wpp.api.ws.binary.protos.ProductListHeaderImage getHeaderImage();
  /**
   * <code>optional .binary.ProductListHeaderImage headerImage = 2;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.ProductListHeaderImageOrBuilder getHeaderImageOrBuilder();

  /**
   * <code>optional string businessOwnerJid = 3;</code>
   * @return Whether the businessOwnerJid field is set.
   */
  boolean hasBusinessOwnerJid();
  /**
   * <code>optional string businessOwnerJid = 3;</code>
   * @return The businessOwnerJid.
   */
  java.lang.String getBusinessOwnerJid();
  /**
   * <code>optional string businessOwnerJid = 3;</code>
   * @return The bytes for businessOwnerJid.
   */
  com.google.protobuf.ByteString
      getBusinessOwnerJidBytes();
}
