// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

/**
 * Protobuf type {@code binary.Point}
 */
public final class Point extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:binary.Point)
    PointOrBuilder {
private static final long serialVersionUID = 0L;
  // Use Point.newBuilder() to construct.
  private Point(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private Point() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new Point();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private Point(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    this();
    if (extensionRegistry == null) {
      throw new java.lang.NullPointerException();
    }
    int mutable_bitField0_ = 0;
    com.google.protobuf.UnknownFieldSet.Builder unknownFields =
        com.google.protobuf.UnknownFieldSet.newBuilder();
    try {
      boolean done = false;
      while (!done) {
        int tag = input.readTag();
        switch (tag) {
          case 0:
            done = true;
            break;
          case 8: {
            bitField0_ |= 0x00000001;
            xDeprecated_ = input.readInt32();
            break;
          }
          case 16: {
            bitField0_ |= 0x00000002;
            yDeprecated_ = input.readInt32();
            break;
          }
          case 25: {
            bitField0_ |= 0x00000004;
            x_ = input.readDouble();
            break;
          }
          case 33: {
            bitField0_ |= 0x00000008;
            y_ = input.readDouble();
            break;
          }
          default: {
            if (!parseUnknownField(
                input, unknownFields, extensionRegistry, tag)) {
              done = true;
            }
            break;
          }
        }
      }
    } catch (com.google.protobuf.InvalidProtocolBufferException e) {
      throw e.setUnfinishedMessage(this);
    } catch (java.io.IOException e) {
      throw new com.google.protobuf.InvalidProtocolBufferException(
          e).setUnfinishedMessage(this);
    } finally {
      this.unknownFields = unknownFields.build();
      makeExtensionsImmutable();
    }
  }
  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_Point_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_Point_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            br.com.zapia.wpp.api.ws.binary.protos.Point.class, br.com.zapia.wpp.api.ws.binary.protos.Point.Builder.class);
  }

  private int bitField0_;
  public static final int XDEPRECATED_FIELD_NUMBER = 1;
  private int xDeprecated_;
  /**
   * <code>optional int32 xDeprecated = 1;</code>
   * @return Whether the xDeprecated field is set.
   */
  @java.lang.Override
  public boolean hasXDeprecated() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>optional int32 xDeprecated = 1;</code>
   * @return The xDeprecated.
   */
  @java.lang.Override
  public int getXDeprecated() {
    return xDeprecated_;
  }

  public static final int YDEPRECATED_FIELD_NUMBER = 2;
  private int yDeprecated_;
  /**
   * <code>optional int32 yDeprecated = 2;</code>
   * @return Whether the yDeprecated field is set.
   */
  @java.lang.Override
  public boolean hasYDeprecated() {
    return ((bitField0_ & 0x00000002) != 0);
  }
  /**
   * <code>optional int32 yDeprecated = 2;</code>
   * @return The yDeprecated.
   */
  @java.lang.Override
  public int getYDeprecated() {
    return yDeprecated_;
  }

  public static final int X_FIELD_NUMBER = 3;
  private double x_;
  /**
   * <code>optional double x = 3;</code>
   * @return Whether the x field is set.
   */
  @java.lang.Override
  public boolean hasX() {
    return ((bitField0_ & 0x00000004) != 0);
  }
  /**
   * <code>optional double x = 3;</code>
   * @return The x.
   */
  @java.lang.Override
  public double getX() {
    return x_;
  }

  public static final int Y_FIELD_NUMBER = 4;
  private double y_;
  /**
   * <code>optional double y = 4;</code>
   * @return Whether the y field is set.
   */
  @java.lang.Override
  public boolean hasY() {
    return ((bitField0_ & 0x00000008) != 0);
  }
  /**
   * <code>optional double y = 4;</code>
   * @return The y.
   */
  @java.lang.Override
  public double getY() {
    return y_;
  }

  private byte memoizedIsInitialized = -1;
  @java.lang.Override
  public final boolean isInitialized() {
    byte isInitialized = memoizedIsInitialized;
    if (isInitialized == 1) return true;
    if (isInitialized == 0) return false;

    memoizedIsInitialized = 1;
    return true;
  }

  @java.lang.Override
  public void writeTo(com.google.protobuf.CodedOutputStream output)
                      throws java.io.IOException {
    if (((bitField0_ & 0x00000001) != 0)) {
      output.writeInt32(1, xDeprecated_);
    }
    if (((bitField0_ & 0x00000002) != 0)) {
      output.writeInt32(2, yDeprecated_);
    }
    if (((bitField0_ & 0x00000004) != 0)) {
      output.writeDouble(3, x_);
    }
    if (((bitField0_ & 0x00000008) != 0)) {
      output.writeDouble(4, y_);
    }
    unknownFields.writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (((bitField0_ & 0x00000001) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeInt32Size(1, xDeprecated_);
    }
    if (((bitField0_ & 0x00000002) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeInt32Size(2, yDeprecated_);
    }
    if (((bitField0_ & 0x00000004) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeDoubleSize(3, x_);
    }
    if (((bitField0_ & 0x00000008) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeDoubleSize(4, y_);
    }
    size += unknownFields.getSerializedSize();
    memoizedSize = size;
    return size;
  }

  @java.lang.Override
  public boolean equals(final java.lang.Object obj) {
    if (obj == this) {
     return true;
    }
    if (!(obj instanceof br.com.zapia.wpp.api.ws.binary.protos.Point)) {
      return super.equals(obj);
    }
    br.com.zapia.wpp.api.ws.binary.protos.Point other = (br.com.zapia.wpp.api.ws.binary.protos.Point) obj;

    if (hasXDeprecated() != other.hasXDeprecated()) return false;
    if (hasXDeprecated()) {
      if (getXDeprecated()
          != other.getXDeprecated()) return false;
    }
    if (hasYDeprecated() != other.hasYDeprecated()) return false;
    if (hasYDeprecated()) {
      if (getYDeprecated()
          != other.getYDeprecated()) return false;
    }
    if (hasX() != other.hasX()) return false;
    if (hasX()) {
      if (java.lang.Double.doubleToLongBits(getX())
          != java.lang.Double.doubleToLongBits(
              other.getX())) return false;
    }
    if (hasY() != other.hasY()) return false;
    if (hasY()) {
      if (java.lang.Double.doubleToLongBits(getY())
          != java.lang.Double.doubleToLongBits(
              other.getY())) return false;
    }
    if (!unknownFields.equals(other.unknownFields)) return false;
    return true;
  }

  @java.lang.Override
  public int hashCode() {
    if (memoizedHashCode != 0) {
      return memoizedHashCode;
    }
    int hash = 41;
    hash = (19 * hash) + getDescriptor().hashCode();
    if (hasXDeprecated()) {
      hash = (37 * hash) + XDEPRECATED_FIELD_NUMBER;
      hash = (53 * hash) + getXDeprecated();
    }
    if (hasYDeprecated()) {
      hash = (37 * hash) + YDEPRECATED_FIELD_NUMBER;
      hash = (53 * hash) + getYDeprecated();
    }
    if (hasX()) {
      hash = (37 * hash) + X_FIELD_NUMBER;
      hash = (53 * hash) + com.google.protobuf.Internal.hashLong(
          java.lang.Double.doubleToLongBits(getX()));
    }
    if (hasY()) {
      hash = (37 * hash) + Y_FIELD_NUMBER;
      hash = (53 * hash) + com.google.protobuf.Internal.hashLong(
          java.lang.Double.doubleToLongBits(getY()));
    }
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.Point parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  @java.lang.Override
  public Builder newBuilderForType() { return newBuilder(); }
  public static Builder newBuilder() {
    return DEFAULT_INSTANCE.toBuilder();
  }
  public static Builder newBuilder(br.com.zapia.wpp.api.ws.binary.protos.Point prototype) {
    return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
  }
  @java.lang.Override
  public Builder toBuilder() {
    return this == DEFAULT_INSTANCE
        ? new Builder() : new Builder().mergeFrom(this);
  }

  @java.lang.Override
  protected Builder newBuilderForType(
      com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
    Builder builder = new Builder(parent);
    return builder;
  }
  /**
   * Protobuf type {@code binary.Point}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:binary.Point)
      br.com.zapia.wpp.api.ws.binary.protos.PointOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_Point_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_Point_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              br.com.zapia.wpp.api.ws.binary.protos.Point.class, br.com.zapia.wpp.api.ws.binary.protos.Point.Builder.class);
    }

    // Construct using br.com.zapia.wpp.api.ws.binary.protos.Point.newBuilder()
    private Builder() {
      maybeForceBuilderInitialization();
    }

    private Builder(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      super(parent);
      maybeForceBuilderInitialization();
    }
    private void maybeForceBuilderInitialization() {
      if (com.google.protobuf.GeneratedMessageV3
              .alwaysUseFieldBuilders) {
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      xDeprecated_ = 0;
      bitField0_ = (bitField0_ & ~0x00000001);
      yDeprecated_ = 0;
      bitField0_ = (bitField0_ & ~0x00000002);
      x_ = 0D;
      bitField0_ = (bitField0_ & ~0x00000004);
      y_ = 0D;
      bitField0_ = (bitField0_ & ~0x00000008);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_Point_descriptor;
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.Point getDefaultInstanceForType() {
      return br.com.zapia.wpp.api.ws.binary.protos.Point.getDefaultInstance();
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.Point build() {
      br.com.zapia.wpp.api.ws.binary.protos.Point result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.Point buildPartial() {
      br.com.zapia.wpp.api.ws.binary.protos.Point result = new br.com.zapia.wpp.api.ws.binary.protos.Point(this);
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.xDeprecated_ = xDeprecated_;
        to_bitField0_ |= 0x00000001;
      }
      if (((from_bitField0_ & 0x00000002) != 0)) {
        result.yDeprecated_ = yDeprecated_;
        to_bitField0_ |= 0x00000002;
      }
      if (((from_bitField0_ & 0x00000004) != 0)) {
        result.x_ = x_;
        to_bitField0_ |= 0x00000004;
      }
      if (((from_bitField0_ & 0x00000008) != 0)) {
        result.y_ = y_;
        to_bitField0_ |= 0x00000008;
      }
      result.bitField0_ = to_bitField0_;
      onBuilt();
      return result;
    }

    @java.lang.Override
    public Builder clone() {
      return super.clone();
    }
    @java.lang.Override
    public Builder setField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.setField(field, value);
    }
    @java.lang.Override
    public Builder clearField(
        com.google.protobuf.Descriptors.FieldDescriptor field) {
      return super.clearField(field);
    }
    @java.lang.Override
    public Builder clearOneof(
        com.google.protobuf.Descriptors.OneofDescriptor oneof) {
      return super.clearOneof(oneof);
    }
    @java.lang.Override
    public Builder setRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        int index, java.lang.Object value) {
      return super.setRepeatedField(field, index, value);
    }
    @java.lang.Override
    public Builder addRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.addRepeatedField(field, value);
    }
    @java.lang.Override
    public Builder mergeFrom(com.google.protobuf.Message other) {
      if (other instanceof br.com.zapia.wpp.api.ws.binary.protos.Point) {
        return mergeFrom((br.com.zapia.wpp.api.ws.binary.protos.Point)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(br.com.zapia.wpp.api.ws.binary.protos.Point other) {
      if (other == br.com.zapia.wpp.api.ws.binary.protos.Point.getDefaultInstance()) return this;
      if (other.hasXDeprecated()) {
        setXDeprecated(other.getXDeprecated());
      }
      if (other.hasYDeprecated()) {
        setYDeprecated(other.getYDeprecated());
      }
      if (other.hasX()) {
        setX(other.getX());
      }
      if (other.hasY()) {
        setY(other.getY());
      }
      this.mergeUnknownFields(other.unknownFields);
      onChanged();
      return this;
    }

    @java.lang.Override
    public final boolean isInitialized() {
      return true;
    }

    @java.lang.Override
    public Builder mergeFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      br.com.zapia.wpp.api.ws.binary.protos.Point parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (br.com.zapia.wpp.api.ws.binary.protos.Point) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }
    private int bitField0_;

    private int xDeprecated_ ;
    /**
     * <code>optional int32 xDeprecated = 1;</code>
     * @return Whether the xDeprecated field is set.
     */
    @java.lang.Override
    public boolean hasXDeprecated() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>optional int32 xDeprecated = 1;</code>
     * @return The xDeprecated.
     */
    @java.lang.Override
    public int getXDeprecated() {
      return xDeprecated_;
    }
    /**
     * <code>optional int32 xDeprecated = 1;</code>
     * @param value The xDeprecated to set.
     * @return This builder for chaining.
     */
    public Builder setXDeprecated(int value) {
      bitField0_ |= 0x00000001;
      xDeprecated_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional int32 xDeprecated = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearXDeprecated() {
      bitField0_ = (bitField0_ & ~0x00000001);
      xDeprecated_ = 0;
      onChanged();
      return this;
    }

    private int yDeprecated_ ;
    /**
     * <code>optional int32 yDeprecated = 2;</code>
     * @return Whether the yDeprecated field is set.
     */
    @java.lang.Override
    public boolean hasYDeprecated() {
      return ((bitField0_ & 0x00000002) != 0);
    }
    /**
     * <code>optional int32 yDeprecated = 2;</code>
     * @return The yDeprecated.
     */
    @java.lang.Override
    public int getYDeprecated() {
      return yDeprecated_;
    }
    /**
     * <code>optional int32 yDeprecated = 2;</code>
     * @param value The yDeprecated to set.
     * @return This builder for chaining.
     */
    public Builder setYDeprecated(int value) {
      bitField0_ |= 0x00000002;
      yDeprecated_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional int32 yDeprecated = 2;</code>
     * @return This builder for chaining.
     */
    public Builder clearYDeprecated() {
      bitField0_ = (bitField0_ & ~0x00000002);
      yDeprecated_ = 0;
      onChanged();
      return this;
    }

    private double x_ ;
    /**
     * <code>optional double x = 3;</code>
     * @return Whether the x field is set.
     */
    @java.lang.Override
    public boolean hasX() {
      return ((bitField0_ & 0x00000004) != 0);
    }
    /**
     * <code>optional double x = 3;</code>
     * @return The x.
     */
    @java.lang.Override
    public double getX() {
      return x_;
    }
    /**
     * <code>optional double x = 3;</code>
     * @param value The x to set.
     * @return This builder for chaining.
     */
    public Builder setX(double value) {
      bitField0_ |= 0x00000004;
      x_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional double x = 3;</code>
     * @return This builder for chaining.
     */
    public Builder clearX() {
      bitField0_ = (bitField0_ & ~0x00000004);
      x_ = 0D;
      onChanged();
      return this;
    }

    private double y_ ;
    /**
     * <code>optional double y = 4;</code>
     * @return Whether the y field is set.
     */
    @java.lang.Override
    public boolean hasY() {
      return ((bitField0_ & 0x00000008) != 0);
    }
    /**
     * <code>optional double y = 4;</code>
     * @return The y.
     */
    @java.lang.Override
    public double getY() {
      return y_;
    }
    /**
     * <code>optional double y = 4;</code>
     * @param value The y to set.
     * @return This builder for chaining.
     */
    public Builder setY(double value) {
      bitField0_ |= 0x00000008;
      y_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional double y = 4;</code>
     * @return This builder for chaining.
     */
    public Builder clearY() {
      bitField0_ = (bitField0_ & ~0x00000008);
      y_ = 0D;
      onChanged();
      return this;
    }
    @java.lang.Override
    public final Builder setUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.setUnknownFields(unknownFields);
    }

    @java.lang.Override
    public final Builder mergeUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.mergeUnknownFields(unknownFields);
    }


    // @@protoc_insertion_point(builder_scope:binary.Point)
  }

  // @@protoc_insertion_point(class_scope:binary.Point)
  private static final br.com.zapia.wpp.api.ws.binary.protos.Point DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new br.com.zapia.wpp.api.ws.binary.protos.Point();
  }

  public static br.com.zapia.wpp.api.ws.binary.protos.Point getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  @java.lang.Deprecated public static final com.google.protobuf.Parser<Point>
      PARSER = new com.google.protobuf.AbstractParser<Point>() {
    @java.lang.Override
    public Point parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new Point(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<Point> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<Point> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public br.com.zapia.wpp.api.ws.binary.protos.Point getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

