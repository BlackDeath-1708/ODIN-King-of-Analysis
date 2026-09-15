@load base/protocols/conn

redef Log::default_writer = Log::WRITER_ASCII;
redef LogAscii::use_json = T;
