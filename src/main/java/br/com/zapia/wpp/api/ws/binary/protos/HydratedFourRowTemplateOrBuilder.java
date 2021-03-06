// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

public interface HydratedFourRowTemplateOrBuilder extends
    // @@protoc_insertion_point(interface_extends:binary.HydratedFourRowTemplate)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>optional string hydratedContentText = 6;</code>
   * @return Whether the hydratedContentText field is set.
   */
  boolean hasHydratedContentText();
  /**
   * <code>optional string hydratedContentText = 6;</code>
   * @return The hydratedContentText.
   */
  java.lang.String getHydratedContentText();
  /**
   * <code>optional string hydratedContentText = 6;</code>
   * @return The bytes for hydratedContentText.
   */
  com.google.protobuf.ByteString
      getHydratedContentTextBytes();

  /**
   * <code>optional string hydratedFooterText = 7;</code>
   * @return Whether the hydratedFooterText field is set.
   */
  boolean hasHydratedFooterText();
  /**
   * <code>optional string hydratedFooterText = 7;</code>
   * @return The hydratedFooterText.
   */
  java.lang.String getHydratedFooterText();
  /**
   * <code>optional string hydratedFooterText = 7;</code>
   * @return The bytes for hydratedFooterText.
   */
  com.google.protobuf.ByteString
      getHydratedFooterTextBytes();

  /**
   * <code>repeated .binary.HydratedTemplateButton hydratedButtons = 8;</code>
   */
  java.util.List<br.com.zapia.wpp.api.ws.binary.protos.HydratedTemplateButton> 
      getHydratedButtonsList();
  /**
   * <code>repeated .binary.HydratedTemplateButton hydratedButtons = 8;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedTemplateButton getHydratedButtons(int index);
  /**
   * <code>repeated .binary.HydratedTemplateButton hydratedButtons = 8;</code>
   */
  int getHydratedButtonsCount();
  /**
   * <code>repeated .binary.HydratedTemplateButton hydratedButtons = 8;</code>
   */
  java.util.List<? extends br.com.zapia.wpp.api.ws.binary.protos.HydratedTemplateButtonOrBuilder> 
      getHydratedButtonsOrBuilderList();
  /**
   * <code>repeated .binary.HydratedTemplateButton hydratedButtons = 8;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedTemplateButtonOrBuilder getHydratedButtonsOrBuilder(
      int index);

  /**
   * <code>optional string templateId = 9;</code>
   * @return Whether the templateId field is set.
   */
  boolean hasTemplateId();
  /**
   * <code>optional string templateId = 9;</code>
   * @return The templateId.
   */
  java.lang.String getTemplateId();
  /**
   * <code>optional string templateId = 9;</code>
   * @return The bytes for templateId.
   */
  com.google.protobuf.ByteString
      getTemplateIdBytes();

  /**
   * <code>.binary.DocumentMessage documentMessage = 1;</code>
   * @return Whether the documentMessage field is set.
   */
  boolean hasDocumentMessage();
  /**
   * <code>.binary.DocumentMessage documentMessage = 1;</code>
   * @return The documentMessage.
   */
  br.com.zapia.wpp.api.ws.binary.protos.DocumentMessage getDocumentMessage();
  /**
   * <code>.binary.DocumentMessage documentMessage = 1;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.DocumentMessageOrBuilder getDocumentMessageOrBuilder();

  /**
   * <code>string hydratedTitleText = 2;</code>
   * @return Whether the hydratedTitleText field is set.
   */
  boolean hasHydratedTitleText();
  /**
   * <code>string hydratedTitleText = 2;</code>
   * @return The hydratedTitleText.
   */
  java.lang.String getHydratedTitleText();
  /**
   * <code>string hydratedTitleText = 2;</code>
   * @return The bytes for hydratedTitleText.
   */
  com.google.protobuf.ByteString
      getHydratedTitleTextBytes();

  /**
   * <code>.binary.ImageMessage imageMessage = 3;</code>
   * @return Whether the imageMessage field is set.
   */
  boolean hasImageMessage();
  /**
   * <code>.binary.ImageMessage imageMessage = 3;</code>
   * @return The imageMessage.
   */
  br.com.zapia.wpp.api.ws.binary.protos.ImageMessage getImageMessage();
  /**
   * <code>.binary.ImageMessage imageMessage = 3;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.ImageMessageOrBuilder getImageMessageOrBuilder();

  /**
   * <code>.binary.VideoMessage videoMessage = 4;</code>
   * @return Whether the videoMessage field is set.
   */
  boolean hasVideoMessage();
  /**
   * <code>.binary.VideoMessage videoMessage = 4;</code>
   * @return The videoMessage.
   */
  br.com.zapia.wpp.api.ws.binary.protos.VideoMessage getVideoMessage();
  /**
   * <code>.binary.VideoMessage videoMessage = 4;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.VideoMessageOrBuilder getVideoMessageOrBuilder();

  /**
   * <code>.binary.LocationMessage locationMessage = 5;</code>
   * @return Whether the locationMessage field is set.
   */
  boolean hasLocationMessage();
  /**
   * <code>.binary.LocationMessage locationMessage = 5;</code>
   * @return The locationMessage.
   */
  br.com.zapia.wpp.api.ws.binary.protos.LocationMessage getLocationMessage();
  /**
   * <code>.binary.LocationMessage locationMessage = 5;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.LocationMessageOrBuilder getLocationMessageOrBuilder();

  public br.com.zapia.wpp.api.ws.binary.protos.HydratedFourRowTemplate.TitleCase getTitleCase();
}
