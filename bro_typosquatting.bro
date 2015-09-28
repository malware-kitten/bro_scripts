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
local out = vec[|vec|-2] + vec[|vec|-1] + vec[|vec|];

return out;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
	local dist: double;
	for ( i in legit_domains ) {
		local clean_query = typo_split(query);
		dist = levenshtein_distance(clean_query,i);
		if ( 0 < dist && dist < 5) {
			NOTICE([$note=Typosquat,
				$msg = fmt("Request to typosquatted domain name %s",clean_query),
				$sub = fmt("Legitimate domain: %s",i),
				$conn=c]);
				
		}
	}
}
