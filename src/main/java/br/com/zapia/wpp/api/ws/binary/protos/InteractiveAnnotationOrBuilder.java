// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

public interface InteractiveAnnotationOrBuilder extends
    // @@protoc_insertion_point(interface_extends:binary.InteractiveAnnotation)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>repeated .binary.Point polygonVertices = 1;</code>
   */
  java.util.List<br.com.zapia.wpp.api.ws.binary.protos.Point> 
      getPolygonVerticesList();
  /**
   * <code>repeated .binary.Point polygonVertices = 1;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.Point getPolygonVertices(int index);
  /**
   * <code>repeated .binary.Point polygonVertices = 1;</code>
   */
  int getPolygonVerticesCount();
  /**
   * <code>repeated .binary.Point polygonVertices = 1;</code>
   */
  java.util.List<? extends br.com.zapia.wpp.api.ws.binary.protos.PointOrBuilder> 
      getPolygonVerticesOrBuilderList();
  /**
   * <code>repeated .binary.Point polygonVertices = 1;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.PointOrBuilder getPolygonVerticesOrBuilder(
      int index);

  /**
   * <code>.binary.Location location = 2;</code>
   * @return Whether the location field is set.
   */
  boolean hasLocation();
  /**
   * <code>.binary.Location location = 2;</code>
   * @return The location.
   */
  br.com.zapia.wpp.api.ws.binary.protos.Location getLocation();
  /**
   * <code>.binary.Location location = 2;</code>
   */
  br.com.zapia.wpp.api.ws.binary.protos.LocationOrBuilder getLocationOrBuilder();

  public br.com.zapia.wpp.api.ws.binary.protos.InteractiveAnnotation.ActionCase getActionCase();
}
