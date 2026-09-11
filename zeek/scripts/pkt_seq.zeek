##! Per-connection packet-size and inter-arrival-time sequence log.
##!
##! PS 26145 (d) names "packet-size and timing sequences" explicitly as a
##! signal for detecting malware inside encrypted sessions, distinct from
##! JA3/JA3S/JA4 fingerprinting. Zeek's own ssl.log/quic.log carry neither
##! -- this script adds it as a new log stream (pkt_seq.log) joined to
##! ssl.log/quic.log by uid downstream, the same way FlowByteEnricher
##! (backend/stream_consumer.py) already joins conn.log to ssl.log.
##!
##! Design: track the first MAX_PKTS packet sizes and inter-arrival gaps
##! for EVERY connection (bounded per-connection cost -- tracking stops
##! once MAX_PKTS is reached), but only write a log line for connections
##! the SSL or QUIC analyzer actually recognized. Filtering by protocol up
##! front (e.g. a port==443 check in new_packet) was considered and
##! rejected: it would silently miss real TLS/QUIC traffic on non-standard
##! ports, and this prototype's own demo pcaps
##! (traffic_pcaps/attack_tls_malware.pcap) deliberately use a non-443
##! port. The cost is that new_packet runs for every packet on every
##! connection, not just SSL/QUIC ones -- acceptable at this prototype's
##! traffic scale (see ML_MODELS.md's throughput benchmark), not something
##! a production high-throughput deployment would want without narrowing
##! it (e.g. via DPD's analyzer-confirmed event, once a per-analyzer
##! packet hook exists).
##!
##! Protocol tagging is opportunistic, captured during new_packet (checked
##! on every packet, while state is being tracked), NOT re-checked at
##! connection_state_remove -- a real bug found while validating this
##! against real captured QUIC traffic: QUIC::main.zeek calls
##! `delete c$quic` immediately after it logs quic.log's own row (well
##! before connection_state_remove fires for a UDP flow), so `c?$quic` at
##! removal time is always false and every real QUIC connection silently
##! produced zero pkt_seq.log rows until this was caught.
##!
##! A second real bug found in the same validation pass: QUIC's handshake
##! embeds a genuine TLS 1.3 handshake in its CRYPTO frames, and Zeek's
##! QUIC analyzer runs its own embedded SSL analyzer to parse it -- which
##! sets `c$ssl` too (confirmed directly: a real QUIC connection's
##! conn.log row shows `"service":"quic,ssl"`, both set). Checking `c?$ssl`
##! before `c?$quic` therefore mislabeled every real QUIC connection as
##! "ssl". Fixed by using the packet's own transport header as the
##! disambiguator: real plain TLS is always TCP, so an SSL-analyzer match
##! on a UDP packet can only be QUIC's embedded handshake.

module PktSeq;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:    time            &log;
		uid:   string           &log;
		proto: string           &log;  ## "ssl" or "quic" -- which analyzer matched
		sizes: vector of count  &log;  ## first N packet total-IP-lengths, in arrival order
		gaps:  vector of interval &log; ## gap before each packet after the first, seconds
	};

	## Number of leading packets to record per connection. 12 is enough to
	## cover a typical TLS handshake (ClientHello..Finished, ~7-9 packets)
	## plus a couple of early application-data packets, without unbounded
	## per-connection memory growth.
	const max_pkts = 12 &redef;
}

redef record connection += {
	pktseq_sizes:    vector of count    &default=vector();
	pktseq_gaps:     vector of interval &default=vector();
	pktseq_last_ts:  time               &optional;
	pktseq_proto:    string             &optional;
};

event zeek_init() &priority=5
	{
	Log::create_stream(PktSeq::LOG, [$columns=Info, $path="pkt_seq"]);
	}

event new_packet(c: connection, p: pkt_hdr)
	{
	if ( ! c?$pktseq_proto )
		{
		if ( c?$ssl && p?$udp )
			c$pktseq_proto = "quic";  # QUIC's embedded TLS handshake also sets c$ssl
		else if ( c?$ssl )
			c$pktseq_proto = "ssl";
		else if ( c?$quic )
			c$pktseq_proto = "quic";  # caught before c$quic's post-log delete, if ever
		}

	if ( |c$pktseq_sizes| >= max_pkts )
		return;

	local sz: count;
	if ( p?$ip )
		sz = p$ip$len;
	else if ( p?$ip6 )
		sz = p$ip6$len;
	else
		return;

	if ( c?$pktseq_last_ts )
		c$pktseq_gaps[|c$pktseq_gaps|] = network_time() - c$pktseq_last_ts;
	c$pktseq_last_ts = network_time();
	c$pktseq_sizes[|c$pktseq_sizes|] = sz;
	}

event connection_state_remove(c: connection)
	{
	if ( |c$pktseq_sizes| == 0 || ! c?$pktseq_proto )
		return;

	local rec: PktSeq::Info = [$ts=network_time(), $uid=c$uid, $proto=c$pktseq_proto,
	                            $sizes=c$pktseq_sizes, $gaps=c$pktseq_gaps];
	Log::write(PktSeq::LOG, rec);
	}
