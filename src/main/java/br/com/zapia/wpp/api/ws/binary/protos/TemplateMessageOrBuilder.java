// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

public interface TemplateMessageOrBuilder extends
    // @@protoc_insertion_point(interface_extends:binary.TemplateMessage)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>optional .binary.ContextInfo contextInfo = 3;</code>
   * @return Whether the contextInfo field is set.
   */
  boolean hasContextInfo();
  /**
   * <code>optional .binary.ContextInfo contextInfo = 3;</code>
   * @return The contextInfo.
   */
  br.com.zapia.wpp.api.ws.binary.protos.ContextInfo getContextInfo();
  /**
   * <code>optional .binary.ContextInfo contextInfo = 3;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.ContextInfoOrBuilder getContextInfoOrBuilder();

  /**
   * <code>optional .binary.HydratedFourRowTemplate hydratedTemplate = 4;</code>
   * @return Whether the hydratedTemplate field is set.
   */
  boolean hasHydratedTemplate();
  /**
   * <code>optional .binary.HydratedFourRowTemplate hydratedTemplate = 4;</code>
   * @return The hydratedTemplate.
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedFourRowTemplate getHydratedTemplate();
  /**
   * <code>optional .binary.HydratedFourRowTemplate hydratedTemplate = 4;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedFourRowTemplateOrBuilder getHydratedTemplateOrBuilder();

  /**
   * <code>.binary.FourRowTemplate fourRowTemplate = 1;</code>
   * @return Whether the fourRowTemplate field is set.
   */
  boolean hasFourRowTemplate();
  /**
   * <code>.binary.FourRowTemplate fourRowTemplate = 1;</code>
   * @return The fourRowTemplate.
   */
  br.com.zapia.wpp.api.ws.binary.protos.FourRowTemplate getFourRowTemplate();
  /**
   * <code>.binary.FourRowTemplate fourRowTemplate = 1;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.FourRowTemplateOrBuilder getFourRowTemplateOrBuilder();

  /**
   * <code>.binary.HydratedFourRowTemplate hydratedFourRowTemplate = 2;</code>
   * @return Whether the hydratedFourRowTemplate field is set.
   */
  boolean hasHydratedFourRowTemplate();
  /**
   * <code>.binary.HydratedFourRowTemplate hydratedFourRowTemplate = 2;</code>
   * @return The hydratedFourRowTemplate.
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedFourRowTemplate getHydratedFourRowTemplate();
  /**
   * <code>.binary.HydratedFourRowTemplate hydratedFourRowTemplate = 2;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.HydratedFourRowTemplateOrBuilder getHydratedFourRowTemplateOrBuilder();

  public br.com.zapia.wpp.api.ws.binary.protos.TemplateMessage.FormatCase getFormatCase();
}
