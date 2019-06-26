#Author: Nick Hoffman / securitykitten.github.io / @infoseckitten
#Description:  A bro script to find beacons

module BEACON;

@load base/protocols/http

#this is our master collection, we'll use this to store all our information
global master_collection: table[addr,addr] of vector of time  &synchronized;

export {
    redef enum Log::ID += { LOG };
    type Info: record {
        ts: time     &log;
        #id: conn_id  &log;
	local_host:	addr	&log;
	remote_host:	addr	&log;
	entropy:	double	&log;
    };
    global log_beacon: event(rec: Info);
    
    # Add hosts to ignore with: 
    # redef BEACON::whitelist += {192.168.0.1/32, 192.168.1.0/24}
    const whitelist: set [subnet] = set() &redef;

}
event bro_init()
{
    Log::create_stream(BEACON::LOG, [$columns=Info, $ev=log_beacon]);
}

function calculate_entropy(host: addr, server: addr): double 
{
	local collection = master_collection[host,server];
	local entropy: count;
	local length = |collection|;
	local intervals = vector();
	local pmf: table[time] of double;
	local probs: table[time] of double;
	local sum: double;
	sum = 0;
	for (i in collection) {
		if ( i+1 >= length )
			break;
		else {
			intervals[i] = interval_to_double(collection[i+1] - collection[i]);
		}
	}
	
	#i don't like this solution, oh well
	for (i in intervals) {
		if ( intervals[i] !in pmf )
			pmf[intervals[i]] = 1;
		else
			pmf[intervals[i]] += 1;
	}
	#calculate the probabilities
	for (i in intervals) {
		probs[intervals[i]] = pmf[intervals[i]] / |intervals|;
	}
	for (k in probs) {
		sum += probs[k] * (log10(probs[k]) / log10(2.0));
	}
	if (double_to_time(0.0) in probs) {
		if (probs[double_to_time(0.0)] > 0.3)
			sum = 4;
	}
	#debug statement
	#print fmt("host:%s,server:%s,entropy:%s,interval:%s",host,server,|sum|,intervals);
	return |sum|;
}

#we'll start with http posts, in the case that 
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
	#declare variables
	local host: addr;
	local server: addr;
	local ts: time;
	local uid: string;
	local entropy_result: double;
	
	for (sn in whitelist) {
	    if (c$id$resp_h in sn || c$id$orig_h in sn ) 
            return;
        }
        
	if ( method == "POST" || method == "GET" ) {
		#grab the relevant information
		host = c$id$orig_h;
		server = c$id$resp_h;
		ts = c$start_time;
		uid = c$uid;
		if ( [host,server] !in master_collection ){
			master_collection[host,server] = vector(ts) ;
		}
		else {
			master_collection[host,server][|master_collection[host,server]|] = ts;
			if ( |master_collection[host,server]| > 12) {
				entropy_result = calculate_entropy(host,server);
				if (entropy_result < 0.75 ) {
					print fmt("%s - beacon %s and %s", ts, host, server);
					local rec: BEACON::Info = [$ts=ts, $entropy=entropy_result,$local_host=host,$remote_host=server];
					Log::write(BEACON::LOG, rec);
				}
				master_collection[host,server] = vector();
			}
		}
	}
}
