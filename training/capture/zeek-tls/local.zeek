@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/quic
@load ./scripts/pkt_seq

redef Log::default_writer = Log::WRITER_ASCII;
redef LogAscii::use_json = T;
