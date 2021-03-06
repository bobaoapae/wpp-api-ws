// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

/**
 * Protobuf type {@code binary.ClearChatAction}
 */
public final class ClearChatAction extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:binary.ClearChatAction)
    ClearChatActionOrBuilder {
private static final long serialVersionUID = 0L;
  // Use ClearChatAction.newBuilder() to construct.
  private ClearChatAction(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private ClearChatAction() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new ClearChatAction();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private ClearChatAction(
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
            br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.Builder subBuilder = null;
            if (((bitField0_ & 0x00000001) != 0)) {
              subBuilder = messageRange_.toBuilder();
            }
            messageRange_ = input.readMessage(br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.PARSER, extensionRegistry);
            if (subBuilder != null) {
              subBuilder.mergeFrom(messageRange_);
              messageRange_ = subBuilder.buildPartial();
            }
            bitField0_ |= 0x00000001;
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
    return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_ClearChatAction_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_ClearChatAction_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction.class, br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction.Builder.class);
  }

  private int bitField0_;
  public static final int MESSAGERANGE_FIELD_NUMBER = 1;
  private br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange messageRange_;
  /**
   * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
   * @return Whether the messageRange field is set.
   */
  @java.lang.Override
  public boolean hasMessageRange() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
   * @return The messageRange.
   */
  @java.lang.Override
  public br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange getMessageRange() {
    return messageRange_ == null ? br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.getDefaultInstance() : messageRange_;
  }
  /**
   * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
   */
  @java.lang.Override
  public br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRangeOrBuilder getMessageRangeOrBuilder() {
    return messageRange_ == null ? br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.getDefaultInstance() : messageRange_;
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
      output.writeMessage(1, getMessageRange());
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
        .computeMessageSize(1, getMessageRange());
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
    if (!(obj instanceof br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction)) {
      return super.equals(obj);
    }
    br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction other = (br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction) obj;

    if (hasMessageRange() != other.hasMessageRange()) return false;
    if (hasMessageRange()) {
      if (!getMessageRange()
          .equals(other.getMessageRange())) return false;
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
    if (hasMessageRange()) {
      hash = (37 * hash) + MESSAGERANGE_FIELD_NUMBER;
      hash = (53 * hash) + getMessageRange().hashCode();
    }
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parseFrom(
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
  public static Builder newBuilder(br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction prototype) {
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
   * Protobuf type {@code binary.ClearChatAction}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:binary.ClearChatAction)
      br.com.zapia.wpp.api.ws.binary.protos.ClearChatActionOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_ClearChatAction_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_ClearChatAction_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction.class, br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction.Builder.class);
    }

    // Construct using br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction.newBuilder()
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
        getMessageRangeFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      if (messageRangeBuilder_ == null) {
        messageRange_ = null;
      } else {
        messageRangeBuilder_.clear();
      }
      bitField0_ = (bitField0_ & ~0x00000001);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_ClearChatAction_descriptor;
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction getDefaultInstanceForType() {
      return br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction.getDefaultInstance();
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction build() {
      br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction buildPartial() {
      br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction result = new br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction(this);
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        if (messageRangeBuilder_ == null) {
          result.messageRange_ = messageRange_;
        } else {
          result.messageRange_ = messageRangeBuilder_.build();
        }
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
      if (other instanceof br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction) {
        return mergeFrom((br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction other) {
      if (other == br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction.getDefaultInstance()) return this;
      if (other.hasMessageRange()) {
        mergeMessageRange(other.getMessageRange());
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
      br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }
    private int bitField0_;

    private br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange messageRange_;
    private com.google.protobuf.SingleFieldBuilderV3<
        br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange, br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.Builder, br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRangeOrBuilder> messageRangeBuilder_;
    /**
     * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
     * @return Whether the messageRange field is set.
     */
    public boolean hasMessageRange() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
     * @return The messageRange.
     */
    public br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange getMessageRange() {
      if (messageRangeBuilder_ == null) {
        return messageRange_ == null ? br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.getDefaultInstance() : messageRange_;
      } else {
        return messageRangeBuilder_.getMessage();
      }
    }
    /**
     * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
     */
    public Builder setMessageRange(br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange value) {
      if (messageRangeBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        messageRange_ = value;
        onChanged();
      } else {
        messageRangeBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000001;
      return this;
    }
    /**
     * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
     */
    public Builder setMessageRange(
        br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.Builder builderForValue) {
      if (messageRangeBuilder_ == null) {
        messageRange_ = builderForValue.build();
        onChanged();
      } else {
        messageRangeBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000001;
      return this;
    }
    /**
     * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
     */
    public Builder mergeMessageRange(br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange value) {
      if (messageRangeBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
            messageRange_ != null &&
            messageRange_ != br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.getDefaultInstance()) {
          messageRange_ =
            br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.newBuilder(messageRange_).mergeFrom(value).buildPartial();
        } else {
          messageRange_ = value;
        }
        onChanged();
      } else {
        messageRangeBuilder_.mergeFrom(value);
      }
      bitField0_ |= 0x00000001;
      return this;
    }
    /**
     * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
     */
    public Builder clearMessageRange() {
      if (messageRangeBuilder_ == null) {
        messageRange_ = null;
        onChanged();
      } else {
        messageRangeBuilder_.clear();
      }
      bitField0_ = (bitField0_ & ~0x00000001);
      return this;
    }
    /**
     * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
     */
    public br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.Builder getMessageRangeBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getMessageRangeFieldBuilder().getBuilder();
    }
    /**
     * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
     */
    public br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRangeOrBuilder getMessageRangeOrBuilder() {
      if (messageRangeBuilder_ != null) {
        return messageRangeBuilder_.getMessageOrBuilder();
      } else {
        return messageRange_ == null ?
            br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.getDefaultInstance() : messageRange_;
      }
    }
    /**
     * <code>optional .binary.SyncActionMessageRange messageRange = 1;</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange, br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.Builder, br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRangeOrBuilder> 
        getMessageRangeFieldBuilder() {
      if (messageRangeBuilder_ == null) {
        messageRangeBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange, br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRange.Builder, br.com.zapia.wpp.api.ws.binary.protos.SyncActionMessageRangeOrBuilder>(
                getMessageRange(),
                getParentForChildren(),
                isClean());
        messageRange_ = null;
      }
      return messageRangeBuilder_;
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


    // @@protoc_insertion_point(builder_scope:binary.ClearChatAction)
  }

  // @@protoc_insertion_point(class_scope:binary.ClearChatAction)
  private static final br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction();
  }

  public static br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  @java.lang.Deprecated public static final com.google.protobuf.Parser<ClearChatAction>
      PARSER = new com.google.protobuf.AbstractParser<ClearChatAction>() {
    @java.lang.Override
    public ClearChatAction parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new ClearChatAction(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<ClearChatAction> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<ClearChatAction> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public br.com.zapia.wpp.api.ws.binary.protos.ClearChatAction getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

