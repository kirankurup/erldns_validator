# erldns_validator
Erlang based DNS Client to validate a list of IPAddress

DNS Utility to validate a list of IPAddress for the given set of Domain Names. 
Right now only A-TYPE & CNAME Records are handled.

"validate" function accepts filename containing the list of IPAddress & Domain to be matched, and DNS Server IPAddress used for querying.
Result is created in another file "result" and is of the format 
  IPAddress, DomainName, DNS Server Returned IPAddress, match/nomatch

=== Run as ===
$ cat sample
  #IPAddress, Domain
  192.30.253.112, github.com
  192.30.253.111, google.com
$ erl
> dns_validator:validate("sample", "8.8.8.8").
ok

$ cat result
192.30.253.112, github.com, 192.30.253.113, nomatch
192.30.253.111, google.com, 216.58.197.78, nomatch
