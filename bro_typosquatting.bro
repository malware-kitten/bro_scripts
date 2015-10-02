#Author: Nick Hoffman / securitykitten.github.io / @infoseckitten
#Description:  A bro script to find typosquatted domain names within DNS requests

module TYPOSQUAT;

export {
    redef enum Notice::Type += { Typosquat, };
    const legit_domains: set [string] &redef;
    redef legit_domains = {"google.com","microsoft.com"};
}

function typo_split(str: string): string {
    local vec = split_all(str,/\./);
    if (|vec| > 2) {
    	local out = vec[|vec|-2] + vec[|vec|-1] + vec[|vec|];
    	return out;
    }
    return str;
}

function get_max_distance(str: string): double {
    return |str| * 0.2;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
	local dist: double;
        local max_dist: double;
	local length: count = 0;
        local clean_query: string;
	clean_query = typo_split(query);
	for ( i in legit_domains ) {
		#Get the distance and maximum distance
		dist = levenshtein_distance(clean_query,i);
		max_dist = get_max_distance(clean_query);
		
		#Do a length check to make sure that they are a similar length
		if (|query| > |i|)
                        length = |query| - |i|;
                else
                        length = |i| - |query|;
		if (length > 3)
			next;

		#if all the tests pass, then lets fire the alert
		if ( 0 < dist && dist < max_dist) {
			NOTICE([$note=Typosquat,
				$msg = fmt("Request to typosquatted domain name %s",clean_query),
				$sub = fmt("Legitimate domain: %s",i),
				$conn=c]);
				
		}
	}
}
