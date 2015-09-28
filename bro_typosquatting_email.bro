#Author: Nick Hoffman / securitykitten.github.io / @infoseckitten
#Description:  A bro script to find typosquatted domain names within DNS requests

@load base/frameworks/notice/main
@load base/protocols/smtp/main

module SMTP;

export {
    redef enum Notice::Type += { Typosquat };
}
function extract_email(email: string): string_set {
	local temp: string_set ;
	temp = find_all(email, /@[a-zA_Z0-9\.\-]{3,}/);
	#print fmt("%s",temp);
	return temp;
}

event log_smtp(rec: SMTP::Info) {
	local sender: string_set;
	local recipient: string_set;
	local dist: double;
	if ( rec?$mailfrom ) {
		for (i in extract_email(rec$mailfrom)) {
			if ( i !in sender ) {
				#print fmt("added sender %s",i);
				add sender[i];
			}
		}
	}
	if ( rec?$from ) {
		for (i in extract_email(rec$from)) {
			if ( i !in sender ) {
				#print fmt("added sender %s",i);
				add sender[i];
			}
		}
	}
	if ( rec?$reply_to ) {
		for (i in extract_email(rec$reply_to)) {
			if ( i !in sender ) {
				#print fmt("added sender %s",i);
				add sender[i];
			}
		}
	}
	if ( rec?$rcptto ) {
		for ( ppl in rec$rcptto ){
			for ( person in extract_email(ppl) ) {
				if ( person !in recipient ) {
					#print fmt("added recipient %s",person);
					add recipient[person];
				}
			}
		}
	}
	if ( rec?$to ) {
		for ( ppl in rec$to ){
			for ( person in extract_email(ppl) ) {
				if ( person !in recipient ) {
					#print fmt("added recipient %s",person);
					add recipient[person];
				}
			}
		}
	}
	for (i in recipient) {
		for (j in sender) {
			dist = levenshtein_distance(j,i);
			if ( 0 < dist && dist < 5) {
				print fmt("%s,%s",i,j);
				NOTICE([$note=Typosquat,
					$msg = fmt("Email from to typosquatted domains %s to %s",i,j),
					$id=rec$id]);
				
			}
		}
	}	
}
