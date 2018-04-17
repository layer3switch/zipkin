/**
 * Copyright 2015-2018 The OpenZipkin Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package zipkin2.internal;

import com.google.protobuf.ByteString;
import com.google.protobuf.CodedOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.assertj.core.data.MapEntry;
import org.junit.Test;
import zipkin2.codec.SpanBytesDecoder;
import zipkin2.codec.SpanBytesEncoder;
import zipkin2.internal.Proto3Fields.MapEntryField;
import zipkin2.internal.Proto3Fields.Utf8Field;
import zipkin2.internal.Proto3ZipkinFields.AnnotationField;
import zipkin2.internal.Proto3ZipkinFields.EndpointField;
import zipkin2.internal.Proto3ZipkinFields.SpanField;
import zipkin2.proto3.Annotation;
import zipkin2.proto3.Endpoint;
import zipkin2.proto3.ListOfSpans;
import zipkin2.proto3.Span;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.data.MapEntry.entry;

public class Proto3CodecInteropTest {
  static final zipkin2.Endpoint ORDER = zipkin2.Endpoint.newBuilder()
    .serviceName("订单维护服务")
    .ip("2001:db8::c001")
    .build();

  static final zipkin2.Endpoint PROFILE = zipkin2.Endpoint.newBuilder()
    .serviceName("个人信息服务")
    .ip("192.168.99.101")
    .port(9000)
    .build();

  static final zipkin2.Span ZIPKIN_SPAN = zipkin2.Span.newBuilder()
    .traceId("4d1e00c0db9010db86154a4ba6e91385")
    .parentId("86154a4ba6e91385")
    .id("4d1e00c0db9010db")
    .kind(zipkin2.Span.Kind.SERVER)
    .name("个人信息查询")
    .timestamp(1472470996199000L)
    .duration(207000L)
    .localEndpoint(ORDER)
    .remoteEndpoint(PROFILE)
    .addAnnotation(1472470996199000L, "foo happened")
    .putTag("http.path", "/person/profile/query")
    .putTag("http.status_code", "403")
    .putTag("clnt/finagle.version", "6.45.0")
    .putTag("error", "此用户没有操作权限")
    .shared(true)
    .build();
  static final List<zipkin2.Span> ZIPKIN_SPANS = Arrays.asList(ZIPKIN_SPAN, ZIPKIN_SPAN);

  static final Span PROTO_SPAN = Span.newBuilder()
    .setTraceId(decodeHex(ZIPKIN_SPAN.traceId()))
    .setParentId(decodeHex(ZIPKIN_SPAN.parentId()))
    .setId(decodeHex(ZIPKIN_SPAN.id()))
    .setKind(Span.Kind.valueOf(ZIPKIN_SPAN.kind().name()))
    .setName(ZIPKIN_SPAN.name())
    .setTimestamp(ZIPKIN_SPAN.timestampAsLong())
    .setDuration(ZIPKIN_SPAN.durationAsLong())
    .setLocalEndpoint(Endpoint.newBuilder()
      .setServiceName(ORDER.serviceName())
      .setIpv6(ByteString.copyFrom(ORDER.ipv6Bytes())).build()
    )
    .setRemoteEndpoint(Endpoint.newBuilder()
      .setServiceName(PROFILE.serviceName())
      .setIpv4(ByteString.copyFrom(PROFILE.ipv4Bytes()))
      .setPort(PROFILE.portAsInt()).build()
    )
    .addAnnotations(Annotation.newBuilder()
      .setTimestamp(ZIPKIN_SPAN.annotations().get(0).timestamp())
      .setValue(ZIPKIN_SPAN.annotations().get(0).value())
      .build())
    .putAllTags(ZIPKIN_SPAN.tags())
    .setShared(true)
    .build();
  ListOfSpans PROTO_SPANS = ListOfSpans.newBuilder()
    .addSpans(PROTO_SPAN)
    .addSpans(PROTO_SPAN).build();

  @Test public void encodeIsCompatible() throws Exception {
    byte[] buff = new byte[CodedOutputStream.computeMessageSize(1, PROTO_SPAN)];
    CodedOutputStream out = CodedOutputStream.newInstance(buff);
    out.writeMessage(1, PROTO_SPAN);

    assertThat(SpanBytesEncoder.PROTO3.encode(ZIPKIN_SPAN))
      .containsExactly(buff);
  }

  @Test public void decodeOneIsCompatible() throws Exception {
    assertThat(SpanBytesDecoder.PROTO3.decodeOne(PROTO_SPANS.toByteArray()))
      .isEqualTo(ZIPKIN_SPAN);
  }

  @Test public void decodeListIsCompatible() throws Exception {
    assertThat(SpanBytesDecoder.PROTO3.decodeList(PROTO_SPANS.toByteArray()))
      .containsExactly(ZIPKIN_SPAN, ZIPKIN_SPAN);
  }

  @Test public void encodeListIsCompatible_buff() throws Exception {
    byte[] buff = new byte[PROTO_SPANS.getSerializedSize()];
    CodedOutputStream out = CodedOutputStream.newInstance(buff);
    PROTO_SPANS.writeTo(out);

    byte[] zipkin_buff = new byte[10 + buff.length];
    assertThat(SpanBytesEncoder.PROTO3.encodeList(ZIPKIN_SPANS, zipkin_buff, 5))
      .isEqualTo(buff.length);

    assertThat(zipkin_buff)
      .startsWith(0, 0, 0, 0, 0)
      .containsSequence(buff)
      .endsWith(0, 0, 0, 0, 0);
  }

  @Test public void encodeListIsCompatible() throws Exception {
    byte[] buff = new byte[PROTO_SPANS.getSerializedSize()];
    CodedOutputStream out = CodedOutputStream.newInstance(buff);
    PROTO_SPANS.writeTo(out);

    assertThat(SpanBytesEncoder.PROTO3.encodeList(ZIPKIN_SPANS))
      .containsExactly(buff);
  }

  @Test public void span_sizeInBytes_matchesProto3() {
    assertThat(new SpanField().sizeInBytes(ZIPKIN_SPAN))
      .isEqualTo(CodedOutputStream.computeMessageSize(1, PROTO_SPAN));
  }

  @Test public void annotation_sizeInBytes_matchesProto3() {
    zipkin2.Annotation zipkinAnnotation = ZIPKIN_SPAN.annotations().get(0);

    assertThat(new AnnotationField(10).sizeInBytes(zipkinAnnotation))
      .isEqualTo(CodedOutputStream.computeMessageSize(10, Annotation.newBuilder()
        .setTimestamp(zipkinAnnotation.timestamp())
        .setValue(zipkinAnnotation.value())
        .build()))
      .isEqualTo(25); // for the next test
  }

  @Test public void annotation_write_matchesProto3() throws IOException {
    zipkin2.Annotation zipkinAnnotation = ZIPKIN_SPAN.annotations().get(0);
    Buffer buffer = new Buffer(25);

    new AnnotationField(10).write(buffer, zipkinAnnotation);

    Annotation protoAnnotation = PROTO_SPAN.getAnnotations(0);
    byte[] buff = new byte[protoAnnotation.getSerializedSize() + 2];
    CodedOutputStream out = CodedOutputStream.newInstance(buff);
    out.writeMessage(10, protoAnnotation);

    assertThat(buffer.toByteArray())
      .containsExactly(buff);
  }

  @Test public void endpoint_sizeInBytes_matchesProto3() {
    assertThat(new EndpointField(8).sizeInBytes(ZIPKIN_SPAN.localEndpoint()))
      .isEqualTo(CodedOutputStream.computeMessageSize(8, PROTO_SPAN.getLocalEndpoint()));

    assertThat(new EndpointField(9).sizeInBytes(ZIPKIN_SPAN.remoteEndpoint()))
      .isEqualTo(CodedOutputStream.computeMessageSize(9, PROTO_SPAN.getRemoteEndpoint()));
  }

  @Test public void endpoint_write_matchesProto3() throws IOException {
    endpoint_write_matchesProto3(8, ZIPKIN_SPAN.localEndpoint(), PROTO_SPAN.getLocalEndpoint());
    endpoint_write_matchesProto3(9, ZIPKIN_SPAN.remoteEndpoint(), PROTO_SPAN.getRemoteEndpoint());
  }

  void endpoint_write_matchesProto3(int fieldNumber, zipkin2.Endpoint zipkinEndpoint,
    Endpoint protoEndpoint) throws IOException {
    EndpointField field = new EndpointField(fieldNumber);
    Buffer buffer = new Buffer(field.sizeInBytes(zipkinEndpoint));
    field.write(buffer, zipkinEndpoint);

    byte[] buff = new byte[CodedOutputStream.computeMessageSize(fieldNumber, protoEndpoint)];
    CodedOutputStream out = CodedOutputStream.newInstance(buff);
    out.writeMessage(fieldNumber, protoEndpoint);

    assertThat(buffer.toByteArray())
      .containsExactly(buff);
  }

  @Test public void utf8_sizeInBytes_matchesProto3() {
    assertThat(new Utf8Field(1).sizeInBytes(ORDER.serviceName()))
      .isEqualTo(CodedOutputStream.computeStringSize(1, ORDER.serviceName()));
  }

  @Test public void mapEntry_sizeInBytes_matchesProto3() {
    MapEntry<String, String> entry = entry("clnt/finagle.version", "6.45.0");
    assertThat(new MapEntryField(11).sizeInBytes(entry))
      .isEqualTo(Span.newBuilder().putTags(entry.key, entry.value).build().getSerializedSize());
  }

  @Test public void writeMapEntryField_matchesProto3() throws IOException {
    MapEntry<String, String> entry = entry("clnt/finagle.version", "6.45.0");
    MapEntryField field = new MapEntryField(11);
    Buffer buffer = new Buffer(field.sizeInBytes(entry));
    field.write(buffer, entry);

    Span oneField = Span.newBuilder().putTags(entry.key, entry.value).build();
    byte[] buff = new byte[oneField.getSerializedSize()];
    CodedOutputStream out = CodedOutputStream.newInstance(buff);
    oneField.writeTo(out);

    assertThat(buffer.toByteArray())
      .containsExactly(buff);
  }

  static ByteString decodeHex(String s) {
    try {
      return ByteString.copyFrom(Hex.decodeHex(s.toCharArray()));
    } catch (DecoderException e) {
      throw new AssertionError(e);
    }
  }
}
