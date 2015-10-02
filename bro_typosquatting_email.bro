#Author: Nick Hoffman / securitykitten.github.io / @infoseckitten 
#Company: Morphick Inc. / @MorphickDefense
#Description:  A bro script to find typosquatted domain names within SMTP streams
#Except as otherwise noted, the content of this page is licensed under the Creative Commons Attribution 3.0 License, and code samples are licensed under the Apache 2.0 License.

@load base/frameworks/notice/main
@load base/protocols/smtp/main

module SMTP;

export {
    redef enum Notice::Type += { Typosquat };
    const whitelist: string_set &redef;
    const companylist: string_set &redef;

    ##############################################################################################
    # Whitelist is the list of legit sender domains that are triggering FP's and need to be tuned
    ##############################################################################################
    redef whitelist = set("@gmail.com","example.com");

    ##############################################################################################
    # If there are additional company domains that you'd like to check for fuzzy match
    ##############################################################################################
    redef companylist = set("mycompany.com");
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
	local max_dist: double;

	###########################################################################################
	# Check the "Mail From" Field
	###########################################################################################
	if ( rec?$mailfrom ) {
		for (i in extract_email(rec$mailfrom)) {
			if ( i !in sender ) {
				#print fmt("added sender %s",i);
				add sender[i];
			}
		}
	}

	###########################################################################################
	# Check the "From" Field
	###########################################################################################
	if ( rec?$from ) {
		for (i in extract_email(rec$from)) {
			if ( i !in sender ) {
				#print fmt("added sender %s",i);
				add sender[i];
			}
		}
	}
	
	###########################################################################################
	# Check the "reply to" field
	###########################################################################################
	if ( rec?$reply_to ) {
		for (i in extract_email(rec$reply_to)) {
			if ( i !in sender ) {
				#print fmt("added sender %s",i);
				add sender[i];
			}
		}
	}

	###########################################################################################
	# Check the "rcpt to" field
	###########################################################################################
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
	
	############################################################################################
	# Check the "to" field
	############################################################################################
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
	
	#############################################################################################
	# Iterate through both the senders and recipients checking for close distances
	#############################################################################################
	local length: count = 0;
	for (i in recipient) {
		for (j in sender) {

			#next if length is too far off
			if (|j| > |i|)
                               length = |j| - |i|;
                        else
                               length = |i| - |j|;
			if (length > 3)
				next;

			#next if in whitelist
			if (j in whitelist) 
				next;

			#adjust distance based on length
			max_dist = |j| * 0.2;

			dist = levenshtein_distance(j,i);
			if ( 0 < dist && dist < max_dist) {
				#print fmt("%s,%s",i,j);
				NOTICE([$note=Typosquat,
					$msg = fmt("Email from to typosquatted domains %s to %s",i,j),
					$id=rec$id]);
				
			}
		}
	}

	##############################################################################################
	# Iterate through the senders and see if any are within a distance from our company watchlist
	##############################################################################################
	for (j in sender) {
		for (i in companylist){
			dist = levenshtein_distance(j,i);
			max_dist = |j| * 0.2;
			if ( 0 < dist && dist < max_dist) {
                                #print fmt("%s,%s",i,j);
                                NOTICE([$note=Typosquat,
                                        $msg = fmt("Email from to typosquatted domains %s to %s",i,j),
                                        $id=rec$id]);

                        }
		}		
	}	
}
