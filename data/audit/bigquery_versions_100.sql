-- TyposquatShield: Historical version-level metadata export

WITH target_packages AS (
  SELECT package_name
  FROM UNNEST([
    'adcraft',
    'ailyboostbot',
    'assulthimars',
    'asynchttpx',
    'backwwii',
    'beautifulsuop',
    'bicoinlib',
    'bip-utjls',
    'bloxy-api',
    'bprintoor',
    'bytedtrace',
    'cccontrol',
    'ccpep',
    'comedrivewithmeman',
    'connections-api-request',
    'cpupyw',
    'dekugay',
    'discord-api',
    'dscss',
    'duck-test-pkg',
    'eoerbisjxqyv',
    'esqgetpippong',
    'esqhydraedcc',
    'esqmaskpepget',
    'esqmccvvirtual',
    'esqnvidiavmget',
    'esqpostrand',
    'ethaddrlib',
    'eutherium',
    'fakehuop',
    'fretrade',
    'gameintel',
    'gearbest-parser',
    'getcandy',
    'grandint',
    'guikill',
    'habboapp',
    'hellowpkg',
    'isred',
    'karpatkey',
    'kongstrong',
    'kotoraka',
    'learning-curve-projects',
    'libcpugamecc',
    'libnvidiapy',
    'libpywstrvm',
    'librandproofhttp',
    'libsplitpush',
    'libvisaintrand',
    'manyhttp',
    'mecit2',
    'microauth2',
    'mousemovement',
    'nwin64tls',
    'openai-spellchecker',
    'opensar',
    'procwire',
    'py-ccrandom',
    'py-corwd',
    'py-cpucandyultra',
    'py-getosintpyw',
    'py-grandccultra',
    'py-loadcpugui',
    'py-ponggrandnvidia',
    'pycryptographylibv3',
    'pyscks',
    'pythonfontsv2',
    'pyvmdec',
    'ramhttp',
    'randomchoicemas',
    'requstss',
    'selfcontrolloadload',
    'selfcraftpepcontrol',
    'selfededpy',
    'selfgamestring',
    'selfmcstr',
    'selftoolvisaping',
    'selfultrapyw',
    'selfvmad',
    'selfvmreplace',
    'shelley',
    'splitpep',
    'testdontdownloadthis',
    'toneo',
    'tphttppullload',
    'tphydraping',
    'tpnvidiahttpreplace',
    'tpnvidiaver',
    'tposintosintrand',
    'tprepullpush',
    'tpreurlultra',
    'tpultraintelcontrol',
    'tpvercpu',
    'tsesyx',
    'tui-ascii-art',
    'uidesign',
    'urllb3',
    'wacve-utils',
    'ytest-cov',
    'zencleaner'
  ]) AS package_name
)

SELECT
  name AS package_name,
  LOWER(
    REGEXP_REPLACE(name, r'[-_.]+', '-')
  ) AS normalized_name,
  version,
  MIN(upload_time) AS first_upload_time,
  COUNT(*) AS distribution_file_count,
  ARRAY_AGG(
    DISTINCT summary IGNORE NULLS LIMIT 1
  )[SAFE_OFFSET(0)] AS summary,
  ARRAY_AGG(
    DISTINCT requires_python IGNORE NULLS LIMIT 1
  )[SAFE_OFFSET(0)] AS requires_python

FROM `bigquery-public-data.pypi.distribution_metadata`

WHERE LOWER(
  REGEXP_REPLACE(name, r'[-_.]+', '-')
) IN (
  SELECT package_name FROM target_packages
)

GROUP BY
  package_name,
  normalized_name,
  version

ORDER BY
  normalized_name,
  first_upload_time;
