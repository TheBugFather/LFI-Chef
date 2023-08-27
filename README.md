













Encoding Techniques
---

Char	URL-encoded			16-bit unicode		Double URL encoding		Overlong UTF-8 encoding
----	---------------		--------------		-------------------		-----------------------
/			%2f				%u002f OR %u2215	%252f					%c0%af OR %e0%80%af OR %c0%2f

\			%5c				%u005c OR %u2216	%255c					%c0%5c OR %c0%80%5c

.			%2e 			%u002e				%252e					%c0%2e OR %e0%40%ae OR %c0ae

\:          %3a             %u003a              %253a                   %c0%3a OR %e0%80%3a 


Traversal techniques
---
../


Null byte techniques
---
%00/prepend/null/byte/like/this

AND

/append/null/byte/like/this%00