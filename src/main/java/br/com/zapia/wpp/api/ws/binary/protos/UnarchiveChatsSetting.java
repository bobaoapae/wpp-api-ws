// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

/**
 * Protobuf type {@code binary.UnarchiveChatsSetting}
 */
public final class UnarchiveChatsSetting extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:binary.UnarchiveChatsSetting)
    UnarchiveChatsSettingOrBuilder {
private static final long serialVersionUID = 0L;
  // Use UnarchiveChatsSetting.newBuilder() to construct.
  private UnarchiveChatsSetting(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private UnarchiveChatsSetting() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new UnarchiveChatsSetting();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private UnarchiveChatsSetting(
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
            unarchiveChats_ = input.readBool();
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
    return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_UnarchiveChatsSetting_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_UnarchiveChatsSetting_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting.class, br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting.Builder.class);
  }

  private int bitField0_;
  public static final int UNARCHIVECHATS_FIELD_NUMBER = 1;
  private boolean unarchiveChats_;
  /**
   * <code>optional bool unarchiveChats = 1;</code>
   * @return Whether the unarchiveChats field is set.
   */
  @java.lang.Override
  public boolean hasUnarchiveChats() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>optional bool unarchiveChats = 1;</code>
   * @return The unarchiveChats.
   */
  @java.lang.Override
  public boolean getUnarchiveChats() {
    return unarchiveChats_;
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
      output.writeBool(1, unarchiveChats_);
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
        .computeBoolSize(1, unarchiveChats_);
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
    if (!(obj instanceof br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting)) {
      return super.equals(obj);
    }
    br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting other = (br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting) obj;

    if (hasUnarchiveChats() != other.hasUnarchiveChats()) return false;
    if (hasUnarchiveChats()) {
      if (getUnarchiveChats()
          != other.getUnarchiveChats()) return false;
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
    if (hasUnarchiveChats()) {
      hash = (37 * hash) + UNARCHIVECHATS_FIELD_NUMBER;
      hash = (53 * hash) + com.google.protobuf.Internal.hashBoolean(
          getUnarchiveChats());
    }
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parseFrom(
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
  public static Builder newBuilder(br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting prototype) {
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
   * Protobuf type {@code binary.UnarchiveChatsSetting}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:binary.UnarchiveChatsSetting)
      br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSettingOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_UnarchiveChatsSetting_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_UnarchiveChatsSetting_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting.class, br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting.Builder.class);
    }

    // Construct using br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting.newBuilder()
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
      unarchiveChats_ = false;
      bitField0_ = (bitField0_ & ~0x00000001);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_UnarchiveChatsSetting_descriptor;
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting getDefaultInstanceForType() {
      return br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting.getDefaultInstance();
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting build() {
      br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting buildPartial() {
      br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting result = new br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting(this);
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.unarchiveChats_ = unarchiveChats_;
        to_bitField0_ |= 0x00000001;
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
      if (other instanceof br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting) {
        return mergeFrom((br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting other) {
      if (other == br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting.getDefaultInstance()) return this;
      if (other.hasUnarchiveChats()) {
        setUnarchiveChats(other.getUnarchiveChats());
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
      br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }
    private int bitField0_;

    private boolean unarchiveChats_ ;
    /**
     * <code>optional bool unarchiveChats = 1;</code>
     * @return Whether the unarchiveChats field is set.
     */
    @java.lang.Override
    public boolean hasUnarchiveChats() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>optional bool unarchiveChats = 1;</code>
     * @return The unarchiveChats.
     */
    @java.lang.Override
    public boolean getUnarchiveChats() {
      return unarchiveChats_;
    }
    /**
     * <code>optional bool unarchiveChats = 1;</code>
     * @param value The unarchiveChats to set.
     * @return This builder for chaining.
     */
    public Builder setUnarchiveChats(boolean value) {
      bitField0_ |= 0x00000001;
      unarchiveChats_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional bool unarchiveChats = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearUnarchiveChats() {
      bitField0_ = (bitField0_ & ~0x00000001);
      unarchiveChats_ = false;
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


    // @@protoc_insertion_point(builder_scope:binary.UnarchiveChatsSetting)
  }

  // @@protoc_insertion_point(class_scope:binary.UnarchiveChatsSetting)
  private static final br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting();
  }

  public static br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  @java.lang.Deprecated public static final com.google.protobuf.Parser<UnarchiveChatsSetting>
      PARSER = new com.google.protobuf.AbstractParser<UnarchiveChatsSetting>() {
    @java.lang.Override
    public UnarchiveChatsSetting parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new UnarchiveChatsSetting(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<UnarchiveChatsSetting> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<UnarchiveChatsSetting> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public br.com.zapia.wpp.api.ws.binary.protos.UnarchiveChatsSetting getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

