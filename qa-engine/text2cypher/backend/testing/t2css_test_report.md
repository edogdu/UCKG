# T2CSS Test Report

Top-K: 10

## Category 1: Node Lookup Queries
- Q: Find CVEs with base severity high | status=error | count=0 | 29.111s
- Q: List CWE weaknesses about authentication | status=error | count=0 | 13.581s

## Category 2: Relationship Traversal (1-hop)
- Q: Show CVEs related to Microsoft products | status=error | count=0 | 18.944s
- Q: Find CAPEC patterns linked to CWE-79 | status=error | count=0 | 17.677s

## Category 3: Multi-hop Queries
- Q: Find CVEs that map to MITRE techniques via CAPEC | status=error | count=0 | 20.863s
- Q: Show software used by groups that employ a given technique | status=error | count=0 | 20.374s

## Category 4: Aggregation and Counting
- Q: Count CVEs per product vendor | status=error | count=0 | 20.991s
- Q: Find top 5 CWEs with most related CAPECs | status=error | count=0 | 20.741s

## Category 5: Conditional and Boolean
- Q: Find CVEs with severity high and vector string containing AV:N | status=error | count=0 | 18.037s
- Q: Show CAPECs with likelihood High or Severity High | status=error | count=0 | 15.096s

## Category 7: Path Queries (Variable-length)
- Q: Find paths from a group to techniques used by related software | status=error | count=0 | 21.928s
- Q: Explore relationships from a CVE to techniques | status=error | count=0 | 25.02s

## Category 8: Graph Pattern Matching
- Q: Find campaigns that are attributed to a group and use a technique | status=error | count=0 | 23.192s
- Q: Find CAPECs that connect to CWEs and techniques simultaneously | status=error | count=0 | 25.101s

## Category 9: Comparative and Ranking
- Q: Find top 10 products with most CVEs | status=error | count=0 | 23.058s
- Q: Rank techniques by number of associated campaigns | status=error | count=0 | 22.795s
