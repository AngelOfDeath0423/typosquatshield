-- TyposquatShield: Historical metadata coverage audit
-- One result per input package, including packages with no match.

WITH target_packages AS (
  SELECT package_name
  FROM UNNEST([
    'adcraft', 'ailyboostbot', 'assulthimars', 'asynchttpx', 'backwwii', 'beautifulsuop', 'bicoinlib', 'bip-utjls', 'bloxy-api', 'bprintoor', 'bytedtrace', 'cccontrol', 'ccpep', 'comedrivewithmeman', 'connections-api-request', 'cpupyw', 'dekugay', 'discord-api', 'dscss', 'duck-test-pkg', 'eoerbisjxqyv', 'esqgetpippong', 'esqhydraedcc', 'esqmaskpepget', 'esqmccvvirtual', 'esqnvidiavmget', 'esqpostrand', 'ethaddrlib', 'eutherium', 'fakehuop', 'fretrade', 'gameintel', 'gearbest-parser', 'getcandy', 'grandint', 'guikill', 'habboapp', 'hellowpkg', 'isred', 'karpatkey', 'kongstrong', 'kotoraka', 'learning-curve-projects', 'libcpugamecc', 'libnvidiapy', 'libpywstrvm', 'librandproofhttp', 'libsplitpush', 'libvisaintrand', 'manyhttp', 'mecit2', 'microauth2', 'mousemovement', 'nwin64tls', 'openai-spellchecker', 'opensar', 'procwire', 'py-ccrandom', 'py-corwd', 'py-cpucandyultra', 'py-getosintpyw', 'py-grandccultra', 'py-loadcpugui', 'py-ponggrandnvidia', 'pycryptographylibv3', 'pyscks', 'pythonfontsv2', 'pyvmdec', 'ramhttp', 'randomchoicemas', 'requstss', 'selfcontrolloadload', 'selfcraftpepcontrol', 'selfededpy', 'selfgamestring', 'selfmcstr', 'selftoolvisaping', 'selfultrapyw', 'selfvmad', 'selfvmreplace', 'shelley', 'splitpep', 'testdontdownloadthis', 'toneo', 'tphttppullload', 'tphydraping', 'tpnvidiahttpreplace', 'tpnvidiaver', 'tposintosintrand', 'tprepullpush', 'tpreurlultra', 'tpultraintelcontrol', 'tpvercpu', 'tsesyx', 'tui-ascii-art', 'uidesign', 'urllb3', 'wacve-utils', 'ytest-cov', 'zencleaner'
  ]) AS package_name
),
historical AS (
  SELECT
    LOWER(
      REGEXP_REPLACE(name, r'[-_.]+', '-')
    ) AS normalized_name,
    COUNT(*) AS distribution_records,
    COUNT(DISTINCT version) AS version_count,
    MIN(upload_time) AS earliest_upload,
    MAX(upload_time) AS latest_upload
  FROM `bigquery-public-data.pypi.distribution_metadata`
  WHERE LOWER(
    REGEXP_REPLACE(name, r'[-_.]+', '-')
  ) IN (SELECT package_name FROM target_packages)
  GROUP BY normalized_name
)
SELECT
  t.package_name,
  COALESCE(h.distribution_records, 0) AS distribution_records,
  COALESCE(h.version_count, 0) AS version_count,
  h.earliest_upload,
  h.latest_upload,
  h.distribution_records IS NOT NULL AS metadata_found
FROM target_packages t
LEFT JOIN historical h
  ON t.package_name = h.normalized_name
ORDER BY t.package_name;
