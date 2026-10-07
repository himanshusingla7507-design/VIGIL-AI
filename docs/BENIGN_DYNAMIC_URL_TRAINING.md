# Verified Benign Dynamic URL Training Experiment

## DO NOT PROMOTE

Production artifacts were not modified. All candidates and thresholds are experimental.

## Sources and provenance

Collected 435 benign dynamic URLs from 17 first-party sources on 2026-10-07.

URLs are existing same-registered-domain links parsed from publicly accessible source pages, then individually fetched over certificate-validated HTTPS. Only successful 2xx responses whose final registered domain stayed within that same source domain are labeled legitimate. The original href was retained; no query/path/fragment components were synthesized. Each CSV row includes its source page, source, reason, status, final URL, and collection date.

| Source | Verified URLs | Categories | Collection date |
|---|---:|---|---|
| Wikimedia Wikipedia | 23 | encoded_query: 5, fragment: 8, high_entropy_legitimate: 3, multiple_query_parameters: 3, path_only: 3, redirect_style: 1 | 2026-10-07 |
| Mozilla Developer Network | 30 | fragment: 10, high_entropy_legitimate: 10, path_only: 10 | 2026-10-07 |
| GitHub | 29 | encoded_query: 3, fragment: 1, high_entropy_legitimate: 8, multiple_query_parameters: 1, path_only: 5, path_query: 10, tracking_parameters: 1 | 2026-10-07 |
| NASA | 36 | encoded_query: 8, high_entropy_legitimate: 8, path_only: 9, path_query: 6, query_only: 5 | 2026-10-07 |
| Library of Congress | 10 | high_entropy_legitimate: 4, path_only: 6 | 2026-10-07 |
| World Wide Web Consortium | 30 | fragment: 8, high_entropy_legitimate: 10, path_only: 10, path_query: 2 | 2026-10-07 |
| Internet Engineering Task Force | 30 | fragment: 10, high_entropy_legitimate: 10, path_only: 10 | 2026-10-07 |
| arXiv | 30 | encoded_query: 10, multiple_query_parameters: 10, path_only: 10 | 2026-10-07 |
| OpenStreetMap | 35 | encoded_query: 4, fragment: 2, high_entropy_legitimate: 6, multiple_query_parameters: 7, path_only: 8, path_query: 8 | 2026-10-07 |
| World Health Organization | 35 | fragment: 8, high_entropy_legitimate: 8, long_legitimate_url: 3, multiple_query_parameters: 2, path_only: 9, path_query: 5 | 2026-10-07 |
| Massachusetts Institute of Technology | 21 | encoded_query: 1, fragment: 3, high_entropy_legitimate: 4, multiple_query_parameters: 1, path_only: 10, tracking_parameters: 2 | 2026-10-07 |
| Stanford University | 9 | high_entropy_legitimate: 2, multiple_query_parameters: 1, path_only: 6 | 2026-10-07 |
| University of California, Berkeley | 30 | fragment: 8, high_entropy_legitimate: 10, multiple_query_parameters: 1, path_only: 10, path_query: 1 | 2026-10-07 |
| GOV.UK | 24 | encoded_query: 1, high_entropy_legitimate: 10, path_only: 10, path_query: 3 | 2026-10-07 |
| European Space Agency | 23 | fragment: 3, high_entropy_legitimate: 10, path_only: 10 | 2026-10-07 |
| Chrome for Developers | 17 | fragment: 1, high_entropy_legitimate: 5, path_only: 10, path_query: 1 | 2026-10-07 |
| RFC Editor | 23 | high_entropy_legitimate: 10, path_only: 10, path_query: 3 | 2026-10-07 |

## Cleaning, deduplication, and domain split

Exact duplicates removed: 0; normalized duplicates removed: 0; duplicates against the existing labeled corpus removed: 0.

Dynamic cohort split by registered domain: train domains **7**, validation domains **10**, overlap **0**. Training/calibration/threshold/test partitions are pairwise registered-domain disjoint.

## Cohort counts

| Category | URLs |
|---|---:|
| path_only | 146 |
| query_only | 5 |
| path_query | 39 |
| multiple_query_parameters | 26 |
| long_query | 0 |
| encoded_query | 32 |
| fragment | 62 |
| tracking_parameters | 3 |
| redirect_style | 1 |
| high_entropy_legitimate | 118 |
| long_legitimate_url | 3 |

Zero-count categories are disclosed rather than synthetically filled; no dataset row is labeled from model predictions.

## Feature distributions

Values are per URL; mean, median, and p90 are reported for the three requested label cohorts.

| Feature | Existing legitimate median (p90) | New dynamic legitimate median (p90) | Phishing median (p90) |
|---|---:|---:|---:|
| URLLength | 22.000 (29.000) | 55.000 (100.600) | 50.000 (130.000) |
| PathLength | 0.000 (0.000) | 25.000 (72.000) | 13.000 (60.000) |
| QueryLength | 0.000 (0.000) | 0.000 (33.600) | 0.000 (42.000) |
| PathSegmentCount | 0.000 (0.000) | 2.000 (5.000) | 1.000 (4.000) |
| QueryParameterCount | 0.000 (0.000) | 0.000 (2.000) | 0.000 (1.000) |
| NoOfQMarkInURL | 0.000 (0.000) | 0.000 (1.000) | 0.000 (1.000) |
| NoOfAmpersandInURL | 0.000 (0.000) | 0.000 (1.000) | 0.000 (0.000) |
| URLPercentEncodingCount | 0.000 (0.000) | 0.000 (0.000) | 0.000 (0.000) |
| URLEntropy | 3.762 (4.011) | 4.291 (4.637) | 4.306 (4.892) |
| DigitRatioInURL | 0.000 (0.000) | 0.000 (0.127) | 0.055 (0.284) |
| NoOfDigitsInURL | 0.000 (0.000) | 0.000 (8.600) | 3.000 (27.000) |

## Candidate model comparison

Primary aggregate metrics are reported on a registered-domain held-out test partition with fixed source weights. Dynamic-legitimate metrics use only new benign URLs in held-out registered domains, reported unweighted. Candidate thresholds are selected on a separate registered-domain threshold partition.

| Model | PR-AUC | ROC-AUC | Precision | Recall | F1 | FNR | FPR | Brier | ECE | Median ms | p95 ms | Size bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| logistic_regression | 0.932888 | 0.883691 | 1.000000 | 0.120098 | 0.214441 | 0.879902 | 0.000000 | 0.132020 | 0.042920 | 0.8472 | 1.1251 | 2,774 |
| random_forest | 0.945282 | 0.913086 | 0.000000 | 0.000000 | 0.000000 | 1.000000 | 0.000000 | 0.111832 | 0.022891 | 15.0241 | 17.4127 | 57,022,575 |
| hist_gradient_boosting | 0.956157 | 0.920798 | 0.000000 | 0.000000 | 0.000000 | 1.000000 | 0.000000 | 0.106699 | 0.028252 | 1.4625 | 1.6847 | 370,311 |

### Dynamic-legitimate held-out metrics

| Model | URLs | FPR | SAFE | SUSPICIOUS | PHISHING |
|---|---:|---:|---:|---:|---:|
| logistic_regression | 60 | 0.0 | 0 | 60 | 0 |
| random_forest | 60 | 0.0 | 0 | 60 | 0 |
| hist_gradient_boosting | 60 | 0.0 | 1 | 59 | 0 |

### Existing legitimate homepage behavior

| Reference/model | URLs | FPR | SAFE | SUSPICIOUS | PHISHING |
|---|---:|---:|---:|---:|---:|
| Production | 26918 | 0.009845 | 3968 | 22685 | 265 |
| logistic_regression | 26918 | 0.000000 | 3915 | 23003 | 0 |
| random_forest | 26918 | 0.000000 | 5287 | 21631 | 0 |
| hist_gradient_boosting | 26918 | 0.000000 | 5218 | 21700 | 0 |

## Regression URLs

| URL | Production probability/verdict | Candidate results |
|---|---|---|
| `https://www.google.com/` | 0.174197 SUSPICIOUS | logistic_regression: 0.108376 SAFE; random_forest: 0.181640 SUSPICIOUS; hist_gradient_boosting: 0.155458 SUSPICIOUS |
| `https://www.google.com/search?q=test` | 0.998018 PHISHING | logistic_regression: 0.154483 SUSPICIOUS; random_forest: 0.948585 SUSPICIOUS; hist_gradient_boosting: 0.957948 SUSPICIOUS |
| `https://www.google.com/search?q=cybersecurity` | 0.997715 PHISHING | logistic_regression: 0.115715 SAFE; random_forest: 0.947566 SUSPICIOUS; hist_gradient_boosting: 0.967739 SUSPICIOUS |
| `https://www.youtube.com/` | 0.167584 SUSPICIOUS | logistic_regression: 0.116451 SAFE; random_forest: 0.181897 SUSPICIOUS; hist_gradient_boosting: 0.156712 SUSPICIOUS |
| `https://www.youtube.com/?feature=ytca` | 0.738847 PHISHING | logistic_regression: 0.084790 SAFE; random_forest: 0.941437 SUSPICIOUS; hist_gradient_boosting: 0.792195 SUSPICIOUS |
| `https://fast.com/` | 0.060029 SAFE | logistic_regression: 0.110758 SAFE; random_forest: 0.116602 SAFE; hist_gradient_boosting: 0.087803 SAFE |

## Phishing regression

Examples below are selected only from already-labeled phishing URLs in held-out domains; they are not synthetic or relabeled. Full per-model predictions are in the JSON report.

### query_strings: 23470 held-out rows
- logistic_regression: recall 0.403281, FNR 0.596719, median probability 0.968030
- random_forest: recall 0.000000, FNR 1.000000, median probability 0.954022
- hist_gradient_boosting: recall 0.000000, FNR 1.000000, median probability 0.972651
- `https://www.ksh.o2o.my/h/citibank/login.php?cmd=3dlogin_submit&id=3d57c7824=`
- `https://rumboaeuropa.site/?fbclid=iwzxh0bgnhzw0bmabhzglkaasacwes3yobhz`
- `https://www.amazon.jp.3mgv.xyz/signin/?openid.pape.max_auth_age=0&openid.return_to=https://www.amazon.co.jp/?ref_=nav_em_hd_re_signin&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.assoc_handle=jpflex&openid.mode=checkid_setup&key=a@b.c&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.ns=http://specs.openid.net/auth/2.0&&ref_=nav_em_hd_clc_signin`
- `https://www.policlinicariovermelho.com.br/home?pag=home`
- `https://support.servicemeta.gq/?update_security_help`

### paths: 102314 held-out rows
- logistic_regression: recall 0.190521, FNR 0.809479, median probability 0.967610
- random_forest: recall 0.000000, FNR 1.000000, median probability 0.954022
- hist_gradient_boosting: recall 0.000000, FNR 1.000000, median probability 0.972478
- `https://www.qrfy.com/p8pbcmgomw`
- `https://www.ksh.o2o.my/h/citibank/login.php?cmd=3dlogin_submit&id=3d57c7824=`
- `https://viasan.life/jp`
- `https://www.amazon.jp.3mgv.xyz/signin/?openid.pape.max_auth_age=0&openid.return_to=https://www.amazon.co.jp/?ref_=nav_em_hd_re_signin&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.assoc_handle=jpflex&openid.mode=checkid_setup&key=a@b.c&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.ns=http://specs.openid.net/auth/2.0&&ref_=nav_em_hd_clc_signin`
- `http://www.kplof.com/tax/home.php`

### login_parameters: 3558 held-out rows
- logistic_regression: recall 0.421023, FNR 0.578977, median probability 0.968035
- random_forest: recall 0.000000, FNR 1.000000, median probability 0.954022
- hist_gradient_boosting: recall 0.000000, FNR 1.000000, median probability 0.972651
- `https://www.transerviciostapatios.com/ppt/na272730s3sud/login/?login.srf&tz2pfja61wrnu0kegxsv93hc8mydoil74bq59hbep5fi18tvd2xy76maculwkrsnog30z4jqzghemt0xi2jfqw4k7c6198vnpbrlys3du5oa.n0goe29yplthzas87dk51miqbcw6juxvrf43a6032krwmb8oniu54c9jzxst7qgedhlfpyv1=cr75b19fdekj2xv8yzutniga4qlm63ohpw0s.n0goe29yplthzas87dk51miqbcw6juxvrf43a6032krwmb8oniu54c9jzxst7qgedhlfpyv1&kamu=ZGZkZmRmZ3MzMjg0NzgyQGpzaGZoa2EuY29t&n0goe29yplthzas87dk51miqbcw6juxvrf43a6032krwmb8oniu54c9jzxst7qgedhlfpyv1=cr75b19fdekj2xv8yzutniga4qlm63ohpw0s`
- `https://mariaalicesouza.com/luiza/?userid=14&amp;uri=r2jvr98aycth+e/8edl2rcqiplsiz/2t18pdxriq1xe=`
- `https://sparkasse-auth.com/files/login.php?user=true`
- `https://verification-center-10003266614.bridalgallerymaryville.com/?processing-verification-account-57253`
- `https://www.marketplace.facebook.com-oh9wq0pzv.isiolo.go.ke/profile.html?countUser=53902fa36517cbe25ae968713de5f929`

### encoded_values: 3639 held-out rows
- logistic_regression: recall 0.463589, FNR 0.536411, median probability 0.968031
- random_forest: recall 0.000000, FNR 1.000000, median probability 0.954022
- hist_gradient_boosting: recall 0.000000, FNR 1.000000, median probability 0.972097
- `https://www.embeddedintel823.tankfilthhounds.net/?country.x=us&locale.x=en_us%3e&client=cb6a65fb7ab25595596e186c81eb9dc9`
- `https://www.ogsoft.cz/modules/mod_simplefileuploadv1.3/elements/shrme/verification/dmn14e52973nc74mn7nm/index.php?country.x=gb-united%20kingdom&lang.x=en`
- `http://u-bla.de-d.jfpaccountant.co.uk/de/reio/index.php?str%d1%96n=i6io4tuih4swc`
- `https://dezembroameaqui.com/?comon%2f=index&amp;amp;id=2&amp;amp;tokenize=fc6c8162e5e3ec260490d9d80754411e`
- `https://magazine-2009.myshopify.com/products/intel-core-i5-9400f-processador-2-9ghz-cache-9mb-6-nucleos-6-threads-9%c2%aa-geracao-lga-1151-bx80684i59400f?utm_source=google&amp;utm_medium=shopping+ads&amp;utm_campaign=multifeed+google+shopping+xml`

### long_urls_over_200: 7254 held-out rows
- logistic_regression: recall 0.853184, FNR 0.146816, median probability 0.968039
- random_forest: recall 0.000000, FNR 1.000000, median probability 0.954022
- hist_gradient_boosting: recall 0.000000, FNR 1.000000, median probability 0.972651
- `https://www.amazon.jp.3mgv.xyz/signin/?openid.pape.max_auth_age=0&openid.return_to=https://www.amazon.co.jp/?ref_=nav_em_hd_re_signin&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.assoc_handle=jpflex&openid.mode=checkid_setup&key=a@b.c&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.ns=http://specs.openid.net/auth/2.0&&ref_=nav_em_hd_clc_signin`
- `https://www.transerviciostapatios.com/ppt/na272730s3sud/login/?login.srf&tz2pfja61wrnu0kegxsv93hc8mydoil74bq59hbep5fi18tvd2xy76maculwkrsnog30z4jqzghemt0xi2jfqw4k7c6198vnpbrlys3du5oa.n0goe29yplthzas87dk51miqbcw6juxvrf43a6032krwmb8oniu54c9jzxst7qgedhlfpyv1=cr75b19fdekj2xv8yzutniga4qlm63ohpw0s.n0goe29yplthzas87dk51miqbcw6juxvrf43a6032krwmb8oniu54c9jzxst7qgedhlfpyv1&kamu=ZGZkZmRmZ3MzMjg0NzgyQGpzaGZoa2EuY29t&n0goe29yplthzas87dk51miqbcw6juxvrf43a6032krwmb8oniu54c9jzxst7qgedhlfpyv1=cr75b19fdekj2xv8yzutniga4qlm63ohpw0s`
- `https://www.royalmail.co.uk-rebook.com/banks/online.citi.eu/login.php?sslchannel=true&sessionid=g1bzq75wlbikjql6zz6qxmstnsimdhwzkwcjvhkscekgfiflsixx2olvdyi4klmlyohcmgawqfnjxtnd3do4jdoir73eedteuf6a1ji9qozzpcw0ftcqycowamqvhetycv`
- `https://www.agitated-volhard.45-146-252-70.plesk.page/index.php/false/false/py1n.html/discovercard.com/dfs/accounthome/summary/-www.schwab.com/secure.accurint.com/unfcu2.org/login1/wachovia.com/myaccounts.aspx/investing.schwab.com/secure/schwab/https:/snsbank.nl/files/files/activityi.html`
- `https://3elsfhvy.robertaocana.com.br/?swahjsdhjsduewuyhjskldi-3rq~hi28a35lx-6jobp6s~ab6i6g4grhqaazovbhl3a73n4-ctavr3tom4mnqmdp3ojdtd578gqamieb-1z3v3ppppyl15cud2726ghlkbas2jpbvot5xr8lckpmvjrqyqgpes1o1-yfeh5fdjrc72g7zrx5ft~92bjypic-4kkg5ul2a1q5h4flfoqhd-lmbzo33c-v2~96yhus-4tm2m-yqo7ajt~p87a437il-ux4b43mm2e8pmtlbec685k5y2mrrchquoma8c4yss5xxsnabbk25vib6h64hp6oialo15hsahjshjduywqyhwhjf8-m45ehhxu8za9vdcc2jjyi6jjdmm44h-i~6cdglmktnezmfu1xhakf1i5~r1rqotuc3xe~bnpkn1l86v58f2k5s9ytn-dxgt4b7jdt~lnbjuxszu6urf~4x7ty4685=value&url=ssomacesac.com/.wwww/bjfkfskl/bwfya21lzwxlckbtew9tyxdhdgvylmnvbq==`

### redirect_parameters: 519 held-out rows
- logistic_regression: recall 0.512524, FNR 0.487476, median probability 0.968038
- random_forest: recall 0.000000, FNR 1.000000, median probability 0.954022
- hist_gradient_boosting: recall 0.000000, FNR 1.000000, median probability 0.972627
- `https://3elsfhvy.robertaocana.com.br/?swahjsdhjsduewuyhjskldi-3rq~hi28a35lx-6jobp6s~ab6i6g4grhqaazovbhl3a73n4-ctavr3tom4mnqmdp3ojdtd578gqamieb-1z3v3ppppyl15cud2726ghlkbas2jpbvot5xr8lckpmvjrqyqgpes1o1-yfeh5fdjrc72g7zrx5ft~92bjypic-4kkg5ul2a1q5h4flfoqhd-lmbzo33c-v2~96yhus-4tm2m-yqo7ajt~p87a437il-ux4b43mm2e8pmtlbec685k5y2mrrchquoma8c4yss5xxsnabbk25vib6h64hp6oialo15hsahjshjduywqyhwhjf8-m45ehhxu8za9vdcc2jjyi6jjdmm44h-i~6cdglmktnezmfu1xhakf1i5~r1rqotuc3xe~bnpkn1l86v58f2k5s9ytn-dxgt4b7jdt~lnbjuxszu6urf~4x7ty4685=value&url=ssomacesac.com/.wwww/bjfkfskl/bwfya21lzwxlckbtew9tyxdhdgvylmnvbq==`
- `https://g5yxcsua.lacarmencita.org/?swahjsdhjsduewuyhjskldi-3rq~hi28a35lx-6jobp6s~ab6i6g4grhqaazovbhl3a73n4-ctavr3tom4mnqmdp3ojdtd578gqamieb-1z3v3ppppyl15cud2726ghlkbas2jpbvot5xr8lckpmvjrqyqgpes1o1-yfeh5fdjrc72g7zrx5ft~92bjypic-4kkg5ul2a1q5h4flfoqhd-lmbzo33c-v2~96yhus-4tm2m-yqo7ajt~p87a437il-ux4b43mm2e8pmtlbec685k5y2mrrchquoma8c4yss5xxsnabbk25vib6h64hp6oialo15hsahjshjduywqyhwhjf8-m45ehhxu8za9vdcc2jjyi6jjdmm44h-i~6cdglmktnezmfu1xhakf1i5~r1rqotuc3xe~bnpkn1l86v58f2k5s9ytn-dxgt4b7jdt~lnbjuxszu6urf~4x7ty4685=value&url=profoto.cl/.poc/dshjdsfhjds/amtydWVnZXJAZm1rYXJjaGl0ZWN0cy5jb20=`
- `https://3fm3y5rw.robertaocana.com.br/?swahjsdhjsduewuyhjskldi-3rq~hi28a35lx-6jobp6s~ab6i6g4grhqaazovbhl3a73n4-ctavr3tom4mnqmdp3ojdtd578gqamieb-1z3v3ppppyl15cud2726ghlkbas2jpbvot5xr8lckpmvjrqyqgpes1o1-yfeh5fdjrc72g7zrx5ft~92bjypic-4kkg5ul2a1q5h4flfoqhd-lmbzo33c-v2~96yhus-4tm2m-yqo7ajt~p87a437il-ux4b43mm2e8pmtlbec685k5y2mrrchquoma8c4yss5xxsnabbk25vib6h64hp6oialo15hsahjshjduywqyhwhjf8-m45ehhxu8za9vdcc2jjyi6jjdmm44h-i~6cdglmktnezmfu1xhakf1i5~r1rqotuc3xe~bnpkn1l86v58f2k5s9ytn-dxgt4b7jdt~lnbjuxszu6urf~4x7ty4685=value&url=ssomacesac.com/.wwww/bjfkfskl/cmpazgf1bwnvbw1lcmnpywwuy29t`
- `https://hdimkuzf.robertaocana.com.br/?swahjsdhjsduewuyhjskldi-3rq~hi28a35lx-6jobp6s~ab6i6g4grhqaazovbhl3a73n4-ctavr3tom4mnqmdp3ojdtd578gqamieb-1z3v3ppppyl15cud2726ghlkbas2jpbvot5xr8lckpmvjrqyqgpes1o1-yfeh5fdjrc72g7zrx5ft~92bjypic-4kkg5ul2a1q5h4flfoqhd-lmbzo33c-v2~96yhus-4tm2m-yqo7ajt~p87a437il-ux4b43mm2e8pmtlbec685k5y2mrrchquoma8c4yss5xxsnabbk25vib6h64hp6oialo15hsahjshjduywqyhwhjf8-m45ehhxu8za9vdcc2jjyi6jjdmm44h-i~6cdglmktnezmfu1xhakf1i5~r1rqotuc3xe~bnpkn1l86v58f2k5s9ytn-dxgt4b7jdt~lnbjuxszu6urf~4x7ty4685=value&url=ssomacesac.com/.wwww/bjfkfskl/c2FsZXNAc3Rld2FyZHNoaXB0ZWNobm9sb2d5LmNvbQ==`
- `http://43.134.233.26/interactivelogin?continue=https://accounts.google.com/?&amp;followup=https://accounts.google.com/?&amp;passive=1209600&amp;xrealip=107.178.200.200&amp;ifkv=awnoghea3x47vq8iowjmra7lbv6vpkkdlvfns6c7pp97bb4fsyipihl00qhd0s6a3vre2jorqea0`

### brand_like_hostnames: 3920 held-out rows
- logistic_regression: recall 0.293878, FNR 0.706122, median probability 0.968017
- random_forest: recall 0.000000, FNR 1.000000, median probability 0.954022
- hist_gradient_boosting: recall 0.000000, FNR 1.000000, median probability 0.972587
- `https://www.amazon.jp.3mgv.xyz/signin/?openid.pape.max_auth_age=0&openid.return_to=https://www.amazon.co.jp/?ref_=nav_em_hd_re_signin&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.assoc_handle=jpflex&openid.mode=checkid_setup&key=a@b.c&openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.ns=http://specs.openid.net/auth/2.0&&ref_=nav_em_hd_clc_signin`
- `https://www.accountappletejapanr.tokyo/api/japan`
- `https://s3.amazonaws.com/appforest_uf/f1675087895842x532383498274006500/ccx.html?email=3mail@b.c`
- `https://www.apple-payupdate.com/login.php?sessionid=2be08edbe41609fc827748360c7b02d1`
- `https://s3.amazonaws.com/appforest_uf/f1672928170901x832944279810371700/e-mail_settings_2023.html?websrc=05i8e-2d663c9oc3oa93a8oxib54i73x50-34a564a6540a46x554-9c5b4--54cd4454xxic-544oic2b48ic83639-96ai2502605-e77xeab-2ib6c6a0888eii76-5de4384b0id35e4-5b65-5855c00555o5-23x3eecaei4a9670i6aex45365443496o44442d83ca0e5ab03044-086-i-b63504i3i&amp;dispatch=5921257785045547650639297849390546933423747591819288257008724545718402134489265070083131783453084931440878298288671073546909601554326157614211152388973961209675135141126118052817444975227751511898946277075462490876892203803393222618&amp;id=54xo-c66e48io44x54049634idaoa8-5biec69560-8-54d674xei95a-3cac5`

## External phishing-only holdout

The 154,931-row holdout was checked after training only. External FPR is undefined because the holdout contains phishing URLs only.

| Model | Recall | FNR | FPR |
|---|---:|---:|---:|
| logistic_regression | 0.154030 | 0.845970 | undefined |
| random_forest | 0.000000 | 1.000000 | undefined |
| hist_gradient_boosting | 0.000000 | 1.000000 | undefined |

## Decision

**DO NOT PROMOTE**

| Candidate | Overall gate | Test recall | External recall | Dynamic FPR | Homepage FPR |
|---|---|---:|---:|---:|---:|
| logistic_regression | False | 0.120098 | 0.154030 | 0.000000 | 0.000000 |
| random_forest | False | 0.000000 | 0.000000 | 0.000000 | 0.000000 |
| hist_gradient_boosting | False | 0.000000 | 0.000000 | 0.000000 | 0.000000 |

### Existing test suite results

| Suite | Result |
|---|---|
| pytest | failed: 1 failed, 14 passed; test_pipeline.py imports _policy_metrics which is absent from the pre-existing modified train_model.py |
| frontend | passed: 3 tests |
| frontend_build | passed |
| extension | passed: 23 tests |
| javascript_syntax | passed: 5 files |

Production promotion is conditional on every gate in the JSON report. This experiment does not promote candidates or alter production model files, feature names, thresholds, frontend, or extension.
