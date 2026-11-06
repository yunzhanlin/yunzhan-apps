package icu.yunzhan.qa.storage;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.os.Process;
import android.os.StatFs;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

/** Independent platform diagnosis; never changes or supplies product code. */
public final class StorageProbe extends Instrumentation {
    @Override public void onCreate(Bundle arguments) { super.onCreate(arguments); start(); }
    @Override public void onStart() {
        Bundle original = new Bundle(); Path owned = null;
        try {
            Context target = getTargetContext();
            if (!"icu.yunzhan.panel".equals(target.getPackageName()) ||
                Process.myUid() != target.getApplicationInfo().uid)
                throw new IllegalStateException("Target sandbox identity required");
            original.putBoolean("actual_target_UID", true);
            Path cache = target.getCacheDir().toPath();
            if (!Files.isDirectory(cache, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(cache))
                throw new IllegalStateException("Original cache must be a directory");
            owned = Files.createTempDirectory(cache, "C68-platform-probe-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            original.putString("owned_child_mode", PosixFilePermissions.toString(
                Files.getPosixFilePermissions(owned, LinkOption.NOFOLLOW_LINKS)));
            original.putLong("statfs_available_bytes", new StatFs(owned.toString()).getAvailableBytes());
            original.putLong("file_available_bytes", owned.toFile().getUsableSpace());
            try {
                original.putLong("nio_available_bytes", Files.getFileStore(owned).getUsableSpace());
                original.putBoolean("nio_succeeded", true);
            } catch (Exception failure) {
                original.putBoolean("nio_succeeded", false);
                original.putString("nio_failure_class", failure.getClass().getName());
                original.putString("nio_failure_reason", "Mount point not found".equals(failure.getMessage())
                    ? "Mount point not found" : "Other original platform failure; private path excluded");
            }
            original.putBoolean("original_product_source_changed", false);
        } catch (Exception failure) {
            original.putString("probe_failure_class", failure.getClass().getName());
        } finally {
            if (owned != null) {
                try { Files.delete(owned); original.putBoolean("owned_empty_child_removed", true); }
                catch (Exception failure) { original.putString("cleanup_failure_class", failure.getClass().getName()); }
            }
        }
        finish(Activity.RESULT_OK, original);
    }
}
