[Draft whitepaper is here](https://docs.google.com/document/d/1oqblaGp9oN11HB1iYz8kSbgmX3DmWsvQgVBopIE9gQs/pub)

HashDNS is a simple replacement/enhancement for the standard DNS system which allows anyone to submit new host entries on a first-come, first-serve basis.

There is no 'central authority' for approving, adding, transferring or deleting entries. Submitters use a proof-of-work algorithm based on HashCash stamps (to prevent forging and DoS attacks) combined with placement of submissions and secure nonce at secure host-controlled URIs as proof of ownership/control of the host for which a name entry is submitted. Domain transfers are conducted by out-of-band negotiations between the current and new owner to place the transfer request and secure nonce on the current and new hosts, respectively, which the update request stamp then references to authenticate the transfer.

For backwards compatibility, entries not found in the HashDNS server's own database fallback to a legacy DNS lookup.

Future work will be to cement the method of peering update request stamps between HashDNS servers, and to write simple cross-platform local HashDNS servers (eg., tray apps or services) for desktop users.

Intended deployment will be both as a regular server-based daemon, and as an easily-installable Windows/Mac/Linux desktop tray app or service so that users can control their own DNS resolution in a user-friendly manner.

Further future work may involve (for desktop tray-app style HashDNS proxies) a configurable 'voting lookup' whereby more than one remote HashDNS server is consulted to arbitrate or notify user of conflicting host mappings, to give the user choice of preferred resolution.