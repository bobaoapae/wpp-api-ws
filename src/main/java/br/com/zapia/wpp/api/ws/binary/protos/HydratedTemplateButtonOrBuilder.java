// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

public interface HydratedTemplateButtonOrBuilder extends
    // @@protoc_insertion_point(interface_extends:binary.HydratedTemplateButton)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>optional uint32 index = 4;</code>
   * @return Whether the index field is set.
   */
  boolean hasIndex();
  /**
   * <code>optional uint32 index = 4;</code>
   * @return The index.
   */
  int getIndex();

  /**
   * <code>.binary.HydratedQuickReplyButton quickReplyButton = 1;</code>
   * @return Whether the quickReplyButton field is set.
   */
  boolean hasQuickReplyButton();
  /**
   * <code>.binary.HydratedQuickReplyButton quickReplyButton = 1;</code>
   * @return The quickReplyButton.
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedQuickReplyButton getQuickReplyButton();
  /**
   * <code>.binary.HydratedQuickReplyButton quickReplyButton = 1;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedQuickReplyButtonOrBuilder getQuickReplyButtonOrBuilder();

  /**
   * <code>.binary.HydratedURLButton urlButton = 2;</code>
   * @return Whether the urlButton field is set.
   */
  boolean hasUrlButton();
  /**
   * <code>.binary.HydratedURLButton urlButton = 2;</code>
   * @return The urlButton.
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedURLButton getUrlButton();
  /**
   * <code>.binary.HydratedURLButton urlButton = 2;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedURLButtonOrBuilder getUrlButtonOrBuilder();

  /**
   * <code>.binary.HydratedCallButton callButton = 3;</code>
   * @return Whether the callButton field is set.
   */
  boolean hasCallButton();
  /**
   * <code>.binary.HydratedCallButton callButton = 3;</code>
   * @return The callButton.
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedCallButton getCallButton();
  /**
   * <code>.binary.HydratedCallButton callButton = 3;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedCallButtonOrBuilder getCallButtonOrBuilder();

  public br.com.zapia.wpp.api.ws.binary.protos.HydratedTemplateButton.HydratedButtonCase getHydratedButtonCase();
}
