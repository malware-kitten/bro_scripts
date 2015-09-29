# Bro IDS Scripts

Simply put, this is just a collection of bro scripts.

## bro_beacons.bro
This is a script that will keep track (in the conn.log) of IP-IP connections.  The time interval between connections will be measured against shannons entropy.  If the entropy is low enough (a value that is configurable in the script) an log will be written of the beacon-like activity.

## bro_typosquatting.bro
This script is a simple measure using a distance algorithm against a list of sites that are provided.  An alert will fire when users hit sites that are slightly off.  This could indicate that either a misspelling or typosquatted domain was found.

## bro_typosquatting_email.bro
This script also uses a distance algorithm to measure domains found in the header that belong to senders against domains that belong to the recipients.  A whitelist can be set, as well as a list of legitimate sites that you would like to monitor.
