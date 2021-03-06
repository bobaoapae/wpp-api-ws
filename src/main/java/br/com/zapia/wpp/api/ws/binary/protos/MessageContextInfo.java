// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

/**
 * Protobuf type {@code binary.MessageContextInfo}
 */
public final class MessageContextInfo extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:binary.MessageContextInfo)
    MessageContextInfoOrBuilder {
private static final long serialVersionUID = 0L;
  // Use MessageContextInfo.newBuilder() to construct.
  private MessageContextInfo(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private MessageContextInfo() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new MessageContextInfo();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private MessageContextInfo(
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
          case 10: {
            br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.Builder subBuilder = null;
            if (((bitField0_ & 0x00000001) != 0)) {
              subBuilder = deviceListMetadata_.toBuilder();
            }
            deviceListMetadata_ = input.readMessage(br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.PARSER, extensionRegistry);
            if (subBuilder != null) {
              subBuilder.mergeFrom(deviceListMetadata_);
              deviceListMetadata_ = subBuilder.buildPartial();
            }
            bitField0_ |= 0x00000001;
            break;
          }
          case 16: {
            bitField0_ |= 0x00000002;
            deviceListMetadataVersion_ = input.readInt32();
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
    return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_MessageContextInfo_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_MessageContextInfo_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo.class, br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo.Builder.class);
  }

  private int bitField0_;
  public static final int DEVICELISTMETADATA_FIELD_NUMBER = 1;
  private br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata deviceListMetadata_;
  /**
   * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
   * @return Whether the deviceListMetadata field is set.
   */
  @java.lang.Override
  public boolean hasDeviceListMetadata() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
   * @return The deviceListMetadata.
   */
  @java.lang.Override
  public br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata getDeviceListMetadata() {
    return deviceListMetadata_ == null ? br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.getDefaultInstance() : deviceListMetadata_;
  }
  /**
   * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
   */
  @java.lang.Override
  public br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadataOrBuilder getDeviceListMetadataOrBuilder() {
    return deviceListMetadata_ == null ? br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.getDefaultInstance() : deviceListMetadata_;
  }

  public static final int DEVICELISTMETADATAVERSION_FIELD_NUMBER = 2;
  private int deviceListMetadataVersion_;
  /**
   * <code>optional int32 deviceListMetadataVersion = 2;</code>
   * @return Whether the deviceListMetadataVersion field is set.
   */
  @java.lang.Override
  public boolean hasDeviceListMetadataVersion() {
    return ((bitField0_ & 0x00000002) != 0);
  }
  /**
   * <code>optional int32 deviceListMetadataVersion = 2;</code>
   * @return The deviceListMetadataVersion.
   */
  @java.lang.Override
  public int getDeviceListMetadataVersion() {
    return deviceListMetadataVersion_;
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
      output.writeMessage(1, getDeviceListMetadata());
    }
    if (((bitField0_ & 0x00000002) != 0)) {
      output.writeInt32(2, deviceListMetadataVersion_);
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
        .computeMessageSize(1, getDeviceListMetadata());
    }
    if (((bitField0_ & 0x00000002) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeInt32Size(2, deviceListMetadataVersion_);
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
    if (!(obj instanceof br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo)) {
      return super.equals(obj);
    }
    br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo other = (br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo) obj;

    if (hasDeviceListMetadata() != other.hasDeviceListMetadata()) return false;
    if (hasDeviceListMetadata()) {
      if (!getDeviceListMetadata()
          .equals(other.getDeviceListMetadata())) return false;
    }
    if (hasDeviceListMetadataVersion() != other.hasDeviceListMetadataVersion()) return false;
    if (hasDeviceListMetadataVersion()) {
      if (getDeviceListMetadataVersion()
          != other.getDeviceListMetadataVersion()) return false;
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
    if (hasDeviceListMetadata()) {
      hash = (37 * hash) + DEVICELISTMETADATA_FIELD_NUMBER;
      hash = (53 * hash) + getDeviceListMetadata().hashCode();
    }
    if (hasDeviceListMetadataVersion()) {
      hash = (37 * hash) + DEVICELISTMETADATAVERSION_FIELD_NUMBER;
      hash = (53 * hash) + getDeviceListMetadataVersion();
    }
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parseFrom(
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
  public static Builder newBuilder(br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo prototype) {
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
   * Protobuf type {@code binary.MessageContextInfo}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:binary.MessageContextInfo)
      br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfoOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_MessageContextInfo_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_MessageContextInfo_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo.class, br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo.Builder.class);
    }

    // Construct using br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo.newBuilder()
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
        getDeviceListMetadataFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      if (deviceListMetadataBuilder_ == null) {
        deviceListMetadata_ = null;
      } else {
        deviceListMetadataBuilder_.clear();
      }
      bitField0_ = (bitField0_ & ~0x00000001);
      deviceListMetadataVersion_ = 0;
      bitField0_ = (bitField0_ & ~0x00000002);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_MessageContextInfo_descriptor;
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo getDefaultInstanceForType() {
      return br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo.getDefaultInstance();
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo build() {
      br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo buildPartial() {
      br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo result = new br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo(this);
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        if (deviceListMetadataBuilder_ == null) {
          result.deviceListMetadata_ = deviceListMetadata_;
        } else {
          result.deviceListMetadata_ = deviceListMetadataBuilder_.build();
        }
        to_bitField0_ |= 0x00000001;
      }
      if (((from_bitField0_ & 0x00000002) != 0)) {
        result.deviceListMetadataVersion_ = deviceListMetadataVersion_;
        to_bitField0_ |= 0x00000002;
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
      if (other instanceof br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo) {
        return mergeFrom((br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo other) {
      if (other == br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo.getDefaultInstance()) return this;
      if (other.hasDeviceListMetadata()) {
        mergeDeviceListMetadata(other.getDeviceListMetadata());
      }
      if (other.hasDeviceListMetadataVersion()) {
        setDeviceListMetadataVersion(other.getDeviceListMetadataVersion());
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
      br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }
    private int bitField0_;

    private br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata deviceListMetadata_;
    private com.google.protobuf.SingleFieldBuilderV3<
        br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata, br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.Builder, br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadataOrBuilder> deviceListMetadataBuilder_;
    /**
     * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
     * @return Whether the deviceListMetadata field is set.
     */
    public boolean hasDeviceListMetadata() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
     * @return The deviceListMetadata.
     */
    public br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata getDeviceListMetadata() {
      if (deviceListMetadataBuilder_ == null) {
        return deviceListMetadata_ == null ? br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.getDefaultInstance() : deviceListMetadata_;
      } else {
        return deviceListMetadataBuilder_.getMessage();
      }
    }
    /**
     * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
     */
    public Builder setDeviceListMetadata(br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata value) {
      if (deviceListMetadataBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        deviceListMetadata_ = value;
        onChanged();
      } else {
        deviceListMetadataBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000001;
      return this;
    }
    /**
     * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
     */
    public Builder setDeviceListMetadata(
        br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.Builder builderForValue) {
      if (deviceListMetadataBuilder_ == null) {
        deviceListMetadata_ = builderForValue.build();
        onChanged();
      } else {
        deviceListMetadataBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000001;
      return this;
    }
    /**
     * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
     */
    public Builder mergeDeviceListMetadata(br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata value) {
      if (deviceListMetadataBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
            deviceListMetadata_ != null &&
            deviceListMetadata_ != br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.getDefaultInstance()) {
          deviceListMetadata_ =
            br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.newBuilder(deviceListMetadata_).mergeFrom(value).buildPartial();
        } else {
          deviceListMetadata_ = value;
        }
        onChanged();
      } else {
        deviceListMetadataBuilder_.mergeFrom(value);
      }
      bitField0_ |= 0x00000001;
      return this;
    }
    /**
     * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
     */
    public Builder clearDeviceListMetadata() {
      if (deviceListMetadataBuilder_ == null) {
        deviceListMetadata_ = null;
        onChanged();
      } else {
        deviceListMetadataBuilder_.clear();
      }
      bitField0_ = (bitField0_ & ~0x00000001);
      return this;
    }
    /**
     * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
     */
    public br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.Builder getDeviceListMetadataBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getDeviceListMetadataFieldBuilder().getBuilder();
    }
    /**
     * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
     */
    public br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadataOrBuilder getDeviceListMetadataOrBuilder() {
      if (deviceListMetadataBuilder_ != null) {
        return deviceListMetadataBuilder_.getMessageOrBuilder();
      } else {
        return deviceListMetadata_ == null ?
            br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.getDefaultInstance() : deviceListMetadata_;
      }
    }
    /**
     * <code>optional .binary.DeviceListMetadata deviceListMetadata = 1;</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata, br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.Builder, br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadataOrBuilder> 
        getDeviceListMetadataFieldBuilder() {
      if (deviceListMetadataBuilder_ == null) {
        deviceListMetadataBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata, br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadata.Builder, br.com.zapia.wpp.api.ws.binary.protos.DeviceListMetadataOrBuilder>(
                getDeviceListMetadata(),
                getParentForChildren(),
                isClean());
        deviceListMetadata_ = null;
      }
      return deviceListMetadataBuilder_;
    }

    private int deviceListMetadataVersion_ ;
    /**
     * <code>optional int32 deviceListMetadataVersion = 2;</code>
     * @return Whether the deviceListMetadataVersion field is set.
     */
    @java.lang.Override
    public boolean hasDeviceListMetadataVersion() {
      return ((bitField0_ & 0x00000002) != 0);
    }
    /**
     * <code>optional int32 deviceListMetadataVersion = 2;</code>
     * @return The deviceListMetadataVersion.
     */
    @java.lang.Override
    public int getDeviceListMetadataVersion() {
      return deviceListMetadataVersion_;
    }
    /**
     * <code>optional int32 deviceListMetadataVersion = 2;</code>
     * @param value The deviceListMetadataVersion to set.
     * @return This builder for chaining.
     */
    public Builder setDeviceListMetadataVersion(int value) {
      bitField0_ |= 0x00000002;
      deviceListMetadataVersion_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional int32 deviceListMetadataVersion = 2;</code>
     * @return This builder for chaining.
     */
    public Builder clearDeviceListMetadataVersion() {
      bitField0_ = (bitField0_ & ~0x00000002);
      deviceListMetadataVersion_ = 0;
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


    // @@protoc_insertion_point(builder_scope:binary.MessageContextInfo)
  }

  // @@protoc_insertion_point(class_scope:binary.MessageContextInfo)
  private static final br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo();
  }

  public static br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  @java.lang.Deprecated public static final com.google.protobuf.Parser<MessageContextInfo>
      PARSER = new com.google.protobuf.AbstractParser<MessageContextInfo>() {
    @java.lang.Override
    public MessageContextInfo parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new MessageContextInfo(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<MessageContextInfo> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<MessageContextInfo> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public br.com.zapia.wpp.api.ws.binary.protos.MessageContextInfo getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

