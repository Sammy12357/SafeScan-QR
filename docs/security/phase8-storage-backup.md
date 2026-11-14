# Phase 8 storage and backup posture

## Private files and public paths

At startup, SafeScan opens the main SQLite database through
`secure_sqlite_path`; the ML URL cache uses the same guard on first use. New
files are created mode `0600`. Existing regular files with broader permissions
are restricted to `0600` before SQLite opens them. A symlink or permission
failure stops the main database startup; the disposable ML cache disables
itself if it cannot be secured. The runtime Docker user remains `safescan`.
Local retained QR uploads are written atomically as mode `0600`, and their
upload directories are mode `0700`; old files are replaced with private copies
on a subsequent write. A separate offline review is needed to identify any
older permissive upload files that are never rewritten.
File-mode changes do not erase data from older SQLite pages, archived copies,
or backups; the separate privacy retention work must account for those.

Only `/app/static` is mounted at `/static`. The configured `DATA_DIR`, the
database, and the ML cache must resolve outside it; the helper rejects paths
inside that mount, including symlinked paths. The intended Render disk is
`/var/data`, outside the public mount. Before release, inspect the actual
Render mount and confirm `stat -c '%a %U %n' /var/data/qr_cache.db`
reports owner-only mode. Check `ml_cache.sqlite` the same way if it exists.
Keep the disk directory itself nonpublic and owned by the service user.

## Object storage permissions

`storage.py` writes retained QR uploads under `qr-uploads/` in one configured
bucket. For **AWS S3**, give the application identity this object-only policy,
replacing the bucket placeholder:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "SafeScanQrUploadsOnly",
    "Effect": "Allow",
    "Action": ["s3:PutObject", "s3:GetObject"],
    "Resource": "arn:aws:s3:::SAFESCAN_PRIVATE_BUCKET/qr-uploads/*"
  }]
}
```

No bucket listing, deletion, ACL, or bucket administration is required by the
upload path. AWS supports this [object ARN prefix and action
scope](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security_iam_service-with-iam.html).
The S3 upload explicitly requests SSE-S3 `AES256`; set a bucket policy that
denies uploads without that header if the bucket is dedicated to SafeScan.
AWS documents the [SSE-S3 policy condition](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html).

The ML model download path currently defaults to `models/final_model.keras`,
outside the policy above. The Docker image already includes
`/app/models/final_model.keras`; set `SAFESCAN_ML2_MODEL_PATH` to that bundled
path and verify the model loads before applying the narrow policy. If an
object-store model is genuinely needed, grant `s3:GetObject` only for its exact
object key and review that separate exception. Do not grant all-bucket reads.

For **Cloudflare R2**, use a token scoped to the one private bucket with Object
Read & Write permission. Cloudflare's [R2 token permissions](https://developers.cloudflare.com/r2/api/tokens/)
include object listing, so a static R2 token is broader than the AWS policy
above. Prefix-scoped [temporary credentials](https://developers.cloudflare.com/api/resources/r2/subresources/temporary_credentials/methods/create/)
are available, but SafeScan does not yet rotate them; that is a release gate
before claiming equivalent prefix isolation. R2 encrypts objects at rest
automatically, and its S3 API [does not support the AWS `x-amz-server-side-encryption`
request header](https://developers.cloudflare.com/r2/api/s3/api/). SafeScan
therefore omits that header for R2. Test a real private-bucket upload and read
with the chosen backend before enabling it. An incomplete S3/R2 configuration
now errors rather than silently using local storage.

## Encrypted offsite backup and restore drill

Render's `/var/data` disk and its automatic daily snapshots are encrypted at
rest, but snapshots are retained for only seven days. Render explicitly
warns against using a disk snapshot to recover a custom database because it
may be inconsistent. Use SQLite's online backup API for `qr_cache.db`, then
encrypt and copy it off the service. See [Render's disk guidance](https://render.com/docs/disks).

1. From a Render shell on the **running disk-backed service**, create a
   private staging directory under `/tmp` (`umask 077`). Run:

   ```sh
   python /app/scripts/security/backup_sqlite.py --source /var/data/qr_cache.db --output /tmp/PRIVATE_STAGING/qr_cache.db
   ```

   The script refuses an existing output, creates mode `0600`, uses SQLite's
   online backup API, and runs `PRAGMA integrity_check` on the copy. It does
   not stop writes or copy a live `-wal` file.
2. Inventory the rest of `/var/data`. Archive retained uploads and other
   durable non-SQLite files separately. Back up each additional durable SQLite
   file with the same online method; caches that can be rebuilt may be omitted
   only after documenting that decision. Avoid archiving a live SQLite file
   and its WAL/SHM as a database backup. Coordinate a short upload maintenance
   window or verify that the archived upload keys match the database snapshot.
3. Stream the staged database and other archive over Render SSH to an operator
   machine and encrypt each stream immediately with an offsite recipient key:

   ```sh
   ssh SERVICE 'cat /tmp/PRIVATE_STAGING/qr_cache.db' | age -r AGE_RECIPIENT -o safescan-db-YYYYMMDD.age
   ```

   Store the encrypted artifacts
   outside Render with access limited to backup operators. Keep the private
   decryption identity separately; a lost identity makes the backup useless.
   Remove staging files after successful transfer. Define retention and a
   recovery-point target before scheduling this procedure.
4. In an isolated staging environment, decrypt a recent backup, verify its
   checksum and SQLite `PRAGMA integrity_check`, restore the copied `/var/data`
   files with owner-only modes, and start the same release image against that
   copy. Check representative account, scan history, and retained-upload reads
   without sending real emails or payments. Record the date, image revision,
   backup age, restore time, and discrepancies. Never run a restore drill over
   the live disk.

No live backup or restore has been run by this draft. An actual encrypted
offsite backup and successful staging restore drill are required before
claiming Phase 8 recovery readiness.
