// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: WAMessage.proto

package br.com.zapia.wpp.api.ws.binary.protos;

/**
 * Protobuf type {@code binary.ExternalBlobReference}
 */
public final class ExternalBlobReference extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:binary.ExternalBlobReference)
    ExternalBlobReferenceOrBuilder {
private static final long serialVersionUID = 0L;
  // Use ExternalBlobReference.newBuilder() to construct.
  private ExternalBlobReference(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private ExternalBlobReference() {
    mediaKey_ = com.google.protobuf.ByteString.EMPTY;
    directPath_ = "";
    handle_ = "";
    fileSha256_ = com.google.protobuf.ByteString.EMPTY;
    fileEncSha256_ = com.google.protobuf.ByteString.EMPTY;
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new ExternalBlobReference();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private ExternalBlobReference(
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
            bitField0_ |= 0x00000001;
            mediaKey_ = input.readBytes();
            break;
          }
          case 18: {
            com.google.protobuf.ByteString bs = input.readBytes();
            bitField0_ |= 0x00000002;
            directPath_ = bs;
            break;
          }
          case 26: {
            com.google.protobuf.ByteString bs = input.readBytes();
            bitField0_ |= 0x00000004;
            handle_ = bs;
            break;
          }
          case 32: {
            bitField0_ |= 0x00000008;
            fileSizeBytes_ = input.readUInt64();
            break;
          }
          case 42: {
            bitField0_ |= 0x00000010;
            fileSha256_ = input.readBytes();
            break;
          }
          case 50: {
            bitField0_ |= 0x00000020;
            fileEncSha256_ = input.readBytes();
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
    return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_ExternalBlobReference_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_ExternalBlobReference_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference.class, br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference.Builder.class);
  }

  private int bitField0_;
  public static final int MEDIAKEY_FIELD_NUMBER = 1;
  private com.google.protobuf.ByteString mediaKey_;
  /**
   * <code>optional bytes mediaKey = 1;</code>
   * @return Whether the mediaKey field is set.
   */
  @java.lang.Override
  public boolean hasMediaKey() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>optional bytes mediaKey = 1;</code>
   * @return The mediaKey.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString getMediaKey() {
    return mediaKey_;
  }

  public static final int DIRECTPATH_FIELD_NUMBER = 2;
  private volatile java.lang.Object directPath_;
  /**
   * <code>optional string directPath = 2;</code>
   * @return Whether the directPath field is set.
   */
  @java.lang.Override
  public boolean hasDirectPath() {
    return ((bitField0_ & 0x00000002) != 0);
  }
  /**
   * <code>optional string directPath = 2;</code>
   * @return The directPath.
   */
  @java.lang.Override
  public java.lang.String getDirectPath() {
    java.lang.Object ref = directPath_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      if (bs.isValidUtf8()) {
        directPath_ = s;
      }
      return s;
    }
  }
  /**
   * <code>optional string directPath = 2;</code>
   * @return The bytes for directPath.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getDirectPathBytes() {
    java.lang.Object ref = directPath_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      directPath_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int HANDLE_FIELD_NUMBER = 3;
  private volatile java.lang.Object handle_;
  /**
   * <code>optional string handle = 3;</code>
   * @return Whether the handle field is set.
   */
  @java.lang.Override
  public boolean hasHandle() {
    return ((bitField0_ & 0x00000004) != 0);
  }
  /**
   * <code>optional string handle = 3;</code>
   * @return The handle.
   */
  @java.lang.Override
  public java.lang.String getHandle() {
    java.lang.Object ref = handle_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      if (bs.isValidUtf8()) {
        handle_ = s;
      }
      return s;
    }
  }
  /**
   * <code>optional string handle = 3;</code>
   * @return The bytes for handle.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getHandleBytes() {
    java.lang.Object ref = handle_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      handle_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int FILESIZEBYTES_FIELD_NUMBER = 4;
  private long fileSizeBytes_;
  /**
   * <code>optional uint64 fileSizeBytes = 4;</code>
   * @return Whether the fileSizeBytes field is set.
   */
  @java.lang.Override
  public boolean hasFileSizeBytes() {
    return ((bitField0_ & 0x00000008) != 0);
  }
  /**
   * <code>optional uint64 fileSizeBytes = 4;</code>
   * @return The fileSizeBytes.
   */
  @java.lang.Override
  public long getFileSizeBytes() {
    return fileSizeBytes_;
  }

  public static final int FILESHA256_FIELD_NUMBER = 5;
  private com.google.protobuf.ByteString fileSha256_;
  /**
   * <code>optional bytes fileSha256 = 5;</code>
   * @return Whether the fileSha256 field is set.
   */
  @java.lang.Override
  public boolean hasFileSha256() {
    return ((bitField0_ & 0x00000010) != 0);
  }
  /**
   * <code>optional bytes fileSha256 = 5;</code>
   * @return The fileSha256.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString getFileSha256() {
    return fileSha256_;
  }

  public static final int FILEENCSHA256_FIELD_NUMBER = 6;
  private com.google.protobuf.ByteString fileEncSha256_;
  /**
   * <code>optional bytes fileEncSha256 = 6;</code>
   * @return Whether the fileEncSha256 field is set.
   */
  @java.lang.Override
  public boolean hasFileEncSha256() {
    return ((bitField0_ & 0x00000020) != 0);
  }
  /**
   * <code>optional bytes fileEncSha256 = 6;</code>
   * @return The fileEncSha256.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString getFileEncSha256() {
    return fileEncSha256_;
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
      output.writeBytes(1, mediaKey_);
    }
    if (((bitField0_ & 0x00000002) != 0)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 2, directPath_);
    }
    if (((bitField0_ & 0x00000004) != 0)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 3, handle_);
    }
    if (((bitField0_ & 0x00000008) != 0)) {
      output.writeUInt64(4, fileSizeBytes_);
    }
    if (((bitField0_ & 0x00000010) != 0)) {
      output.writeBytes(5, fileSha256_);
    }
    if (((bitField0_ & 0x00000020) != 0)) {
      output.writeBytes(6, fileEncSha256_);
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
        .computeBytesSize(1, mediaKey_);
    }
    if (((bitField0_ & 0x00000002) != 0)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, directPath_);
    }
    if (((bitField0_ & 0x00000004) != 0)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(3, handle_);
    }
    if (((bitField0_ & 0x00000008) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeUInt64Size(4, fileSizeBytes_);
    }
    if (((bitField0_ & 0x00000010) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeBytesSize(5, fileSha256_);
    }
    if (((bitField0_ & 0x00000020) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeBytesSize(6, fileEncSha256_);
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
    if (!(obj instanceof br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference)) {
      return super.equals(obj);
    }
    br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference other = (br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference) obj;

    if (hasMediaKey() != other.hasMediaKey()) return false;
    if (hasMediaKey()) {
      if (!getMediaKey()
          .equals(other.getMediaKey())) return false;
    }
    if (hasDirectPath() != other.hasDirectPath()) return false;
    if (hasDirectPath()) {
      if (!getDirectPath()
          .equals(other.getDirectPath())) return false;
    }
    if (hasHandle() != other.hasHandle()) return false;
    if (hasHandle()) {
      if (!getHandle()
          .equals(other.getHandle())) return false;
    }
    if (hasFileSizeBytes() != other.hasFileSizeBytes()) return false;
    if (hasFileSizeBytes()) {
      if (getFileSizeBytes()
          != other.getFileSizeBytes()) return false;
    }
    if (hasFileSha256() != other.hasFileSha256()) return false;
    if (hasFileSha256()) {
      if (!getFileSha256()
          .equals(other.getFileSha256())) return false;
    }
    if (hasFileEncSha256() != other.hasFileEncSha256()) return false;
    if (hasFileEncSha256()) {
      if (!getFileEncSha256()
          .equals(other.getFileEncSha256())) return false;
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
    if (hasMediaKey()) {
      hash = (37 * hash) + MEDIAKEY_FIELD_NUMBER;
      hash = (53 * hash) + getMediaKey().hashCode();
    }
    if (hasDirectPath()) {
      hash = (37 * hash) + DIRECTPATH_FIELD_NUMBER;
      hash = (53 * hash) + getDirectPath().hashCode();
    }
    if (hasHandle()) {
      hash = (37 * hash) + HANDLE_FIELD_NUMBER;
      hash = (53 * hash) + getHandle().hashCode();
    }
    if (hasFileSizeBytes()) {
      hash = (37 * hash) + FILESIZEBYTES_FIELD_NUMBER;
      hash = (53 * hash) + com.google.protobuf.Internal.hashLong(
          getFileSizeBytes());
    }
    if (hasFileSha256()) {
      hash = (37 * hash) + FILESHA256_FIELD_NUMBER;
      hash = (53 * hash) + getFileSha256().hashCode();
    }
    if (hasFileEncSha256()) {
      hash = (37 * hash) + FILEENCSHA256_FIELD_NUMBER;
      hash = (53 * hash) + getFileEncSha256().hashCode();
    }
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parseFrom(
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
  public static Builder newBuilder(br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference prototype) {
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
   * Protobuf type {@code binary.ExternalBlobReference}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:binary.ExternalBlobReference)
      br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReferenceOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_ExternalBlobReference_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_ExternalBlobReference_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference.class, br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference.Builder.class);
    }

    // Construct using br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference.newBuilder()
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
      mediaKey_ = com.google.protobuf.ByteString.EMPTY;
      bitField0_ = (bitField0_ & ~0x00000001);
      directPath_ = "";
      bitField0_ = (bitField0_ & ~0x00000002);
      handle_ = "";
      bitField0_ = (bitField0_ & ~0x00000004);
      fileSizeBytes_ = 0L;
      bitField0_ = (bitField0_ & ~0x00000008);
      fileSha256_ = com.google.protobuf.ByteString.EMPTY;
      bitField0_ = (bitField0_ & ~0x00000010);
      fileEncSha256_ = com.google.protobuf.ByteString.EMPTY;
      bitField0_ = (bitField0_ & ~0x00000020);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return br.com.zapia.wpp.api.ws.binary.protos.WaMessageProtos.internal_static_binary_ExternalBlobReference_descriptor;
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference getDefaultInstanceForType() {
      return br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference.getDefaultInstance();
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference build() {
      br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference buildPartial() {
      br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference result = new br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference(this);
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        to_bitField0_ |= 0x00000001;
      }
      result.mediaKey_ = mediaKey_;
      if (((from_bitField0_ & 0x00000002) != 0)) {
        to_bitField0_ |= 0x00000002;
      }
      result.directPath_ = directPath_;
      if (((from_bitField0_ & 0x00000004) != 0)) {
        to_bitField0_ |= 0x00000004;
      }
      result.handle_ = handle_;
      if (((from_bitField0_ & 0x00000008) != 0)) {
        result.fileSizeBytes_ = fileSizeBytes_;
        to_bitField0_ |= 0x00000008;
      }
      if (((from_bitField0_ & 0x00000010) != 0)) {
        to_bitField0_ |= 0x00000010;
      }
      result.fileSha256_ = fileSha256_;
      if (((from_bitField0_ & 0x00000020) != 0)) {
        to_bitField0_ |= 0x00000020;
      }
      result.fileEncSha256_ = fileEncSha256_;
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
      if (other instanceof br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference) {
        return mergeFrom((br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference other) {
      if (other == br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference.getDefaultInstance()) return this;
      if (other.hasMediaKey()) {
        setMediaKey(other.getMediaKey());
      }
      if (other.hasDirectPath()) {
        bitField0_ |= 0x00000002;
        directPath_ = other.directPath_;
        onChanged();
      }
      if (other.hasHandle()) {
        bitField0_ |= 0x00000004;
        handle_ = other.handle_;
        onChanged();
      }
      if (other.hasFileSizeBytes()) {
        setFileSizeBytes(other.getFileSizeBytes());
      }
      if (other.hasFileSha256()) {
        setFileSha256(other.getFileSha256());
      }
      if (other.hasFileEncSha256()) {
        setFileEncSha256(other.getFileEncSha256());
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
      br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }
    private int bitField0_;

    private com.google.protobuf.ByteString mediaKey_ = com.google.protobuf.ByteString.EMPTY;
    /**
     * <code>optional bytes mediaKey = 1;</code>
     * @return Whether the mediaKey field is set.
     */
    @java.lang.Override
    public boolean hasMediaKey() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>optional bytes mediaKey = 1;</code>
     * @return The mediaKey.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString getMediaKey() {
      return mediaKey_;
    }
    /**
     * <code>optional bytes mediaKey = 1;</code>
     * @param value The mediaKey to set.
     * @return This builder for chaining.
     */
    public Builder setMediaKey(com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  bitField0_ |= 0x00000001;
      mediaKey_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional bytes mediaKey = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearMediaKey() {
      bitField0_ = (bitField0_ & ~0x00000001);
      mediaKey_ = getDefaultInstance().getMediaKey();
      onChanged();
      return this;
    }

    private java.lang.Object directPath_ = "";
    /**
     * <code>optional string directPath = 2;</code>
     * @return Whether the directPath field is set.
     */
    public boolean hasDirectPath() {
      return ((bitField0_ & 0x00000002) != 0);
    }
    /**
     * <code>optional string directPath = 2;</code>
     * @return The directPath.
     */
    public java.lang.String getDirectPath() {
      java.lang.Object ref = directPath_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        if (bs.isValidUtf8()) {
          directPath_ = s;
        }
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>optional string directPath = 2;</code>
     * @return The bytes for directPath.
     */
    public com.google.protobuf.ByteString
        getDirectPathBytes() {
      java.lang.Object ref = directPath_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        directPath_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>optional string directPath = 2;</code>
     * @param value The directPath to set.
     * @return This builder for chaining.
     */
    public Builder setDirectPath(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  bitField0_ |= 0x00000002;
      directPath_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional string directPath = 2;</code>
     * @return This builder for chaining.
     */
    public Builder clearDirectPath() {
      bitField0_ = (bitField0_ & ~0x00000002);
      directPath_ = getDefaultInstance().getDirectPath();
      onChanged();
      return this;
    }
    /**
     * <code>optional string directPath = 2;</code>
     * @param value The bytes for directPath to set.
     * @return This builder for chaining.
     */
    public Builder setDirectPathBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  bitField0_ |= 0x00000002;
      directPath_ = value;
      onChanged();
      return this;
    }

    private java.lang.Object handle_ = "";
    /**
     * <code>optional string handle = 3;</code>
     * @return Whether the handle field is set.
     */
    public boolean hasHandle() {
      return ((bitField0_ & 0x00000004) != 0);
    }
    /**
     * <code>optional string handle = 3;</code>
     * @return The handle.
     */
    public java.lang.String getHandle() {
      java.lang.Object ref = handle_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        if (bs.isValidUtf8()) {
          handle_ = s;
        }
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>optional string handle = 3;</code>
     * @return The bytes for handle.
     */
    public com.google.protobuf.ByteString
        getHandleBytes() {
      java.lang.Object ref = handle_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        handle_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>optional string handle = 3;</code>
     * @param value The handle to set.
     * @return This builder for chaining.
     */
    public Builder setHandle(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  bitField0_ |= 0x00000004;
      handle_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional string handle = 3;</code>
     * @return This builder for chaining.
     */
    public Builder clearHandle() {
      bitField0_ = (bitField0_ & ~0x00000004);
      handle_ = getDefaultInstance().getHandle();
      onChanged();
      return this;
    }
    /**
     * <code>optional string handle = 3;</code>
     * @param value The bytes for handle to set.
     * @return This builder for chaining.
     */
    public Builder setHandleBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  bitField0_ |= 0x00000004;
      handle_ = value;
      onChanged();
      return this;
    }

    private long fileSizeBytes_ ;
    /**
     * <code>optional uint64 fileSizeBytes = 4;</code>
     * @return Whether the fileSizeBytes field is set.
     */
    @java.lang.Override
    public boolean hasFileSizeBytes() {
      return ((bitField0_ & 0x00000008) != 0);
    }
    /**
     * <code>optional uint64 fileSizeBytes = 4;</code>
     * @return The fileSizeBytes.
     */
    @java.lang.Override
    public long getFileSizeBytes() {
      return fileSizeBytes_;
    }
    /**
     * <code>optional uint64 fileSizeBytes = 4;</code>
     * @param value The fileSizeBytes to set.
     * @return This builder for chaining.
     */
    public Builder setFileSizeBytes(long value) {
      bitField0_ |= 0x00000008;
      fileSizeBytes_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional uint64 fileSizeBytes = 4;</code>
     * @return This builder for chaining.
     */
    public Builder clearFileSizeBytes() {
      bitField0_ = (bitField0_ & ~0x00000008);
      fileSizeBytes_ = 0L;
      onChanged();
      return this;
    }

    private com.google.protobuf.ByteString fileSha256_ = com.google.protobuf.ByteString.EMPTY;
    /**
     * <code>optional bytes fileSha256 = 5;</code>
     * @return Whether the fileSha256 field is set.
     */
    @java.lang.Override
    public boolean hasFileSha256() {
      return ((bitField0_ & 0x00000010) != 0);
    }
    /**
     * <code>optional bytes fileSha256 = 5;</code>
     * @return The fileSha256.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString getFileSha256() {
      return fileSha256_;
    }
    /**
     * <code>optional bytes fileSha256 = 5;</code>
     * @param value The fileSha256 to set.
     * @return This builder for chaining.
     */
    public Builder setFileSha256(com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  bitField0_ |= 0x00000010;
      fileSha256_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional bytes fileSha256 = 5;</code>
     * @return This builder for chaining.
     */
    public Builder clearFileSha256() {
      bitField0_ = (bitField0_ & ~0x00000010);
      fileSha256_ = getDefaultInstance().getFileSha256();
      onChanged();
      return this;
    }

    private com.google.protobuf.ByteString fileEncSha256_ = com.google.protobuf.ByteString.EMPTY;
    /**
     * <code>optional bytes fileEncSha256 = 6;</code>
     * @return Whether the fileEncSha256 field is set.
     */
    @java.lang.Override
    public boolean hasFileEncSha256() {
      return ((bitField0_ & 0x00000020) != 0);
    }
    /**
     * <code>optional bytes fileEncSha256 = 6;</code>
     * @return The fileEncSha256.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString getFileEncSha256() {
      return fileEncSha256_;
    }
    /**
     * <code>optional bytes fileEncSha256 = 6;</code>
     * @param value The fileEncSha256 to set.
     * @return This builder for chaining.
     */
    public Builder setFileEncSha256(com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  bitField0_ |= 0x00000020;
      fileEncSha256_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>optional bytes fileEncSha256 = 6;</code>
     * @return This builder for chaining.
     */
    public Builder clearFileEncSha256() {
      bitField0_ = (bitField0_ & ~0x00000020);
      fileEncSha256_ = getDefaultInstance().getFileEncSha256();
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


    // @@protoc_insertion_point(builder_scope:binary.ExternalBlobReference)
  }

  // @@protoc_insertion_point(class_scope:binary.ExternalBlobReference)
  private static final br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference();
  }

  public static br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  @java.lang.Deprecated public static final com.google.protobuf.Parser<ExternalBlobReference>
      PARSER = new com.google.protobuf.AbstractParser<ExternalBlobReference>() {
    @java.lang.Override
    public ExternalBlobReference parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new ExternalBlobReference(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<ExternalBlobReference> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<ExternalBlobReference> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public br.com.zapia.wpp.api.ws.binary.protos.ExternalBlobReference getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

