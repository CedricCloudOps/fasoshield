package bf.fasoshield.agent.ui

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import bf.fasoshield.agent.R
import bf.fasoshield.agent.util.ScanSummary
import java.text.DateFormat
import java.util.Date

class MainActivity : ComponentActivity() {

    private val viewModel: ScanViewModel by viewModels()

    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent {
            MaterialTheme {
                ScanScreen(viewModel)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // All-files access is granted in a system settings screen, and nothing
        // tells the application when the user comes back from it.
        viewModel.refreshFileAccess()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(viewModel: ScanViewModel) {
    val state by viewModel.state.collectAsState()
    Scaffold(
        topBar = { TopAppBar(title = { Text(stringResource(R.string.app_name)) }) },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SummaryRow(state)
            Button(
                onClick = { viewModel.runScan() },
                enabled = !state.scanning,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (state.scanning) {
                    CircularProgressIndicator(
                        Modifier.padding(end = 8.dp),
                        strokeWidth = 2.dp,
                    )
                }
                Text(
                    if (state.scanning) stringResource(R.string.scanning)
                    else stringResource(R.string.scan_now)
                )
            }
            state.error?.let { Text("⚠ $it", color = MaterialTheme.colorScheme.error) }
            if (!state.watchesDownloads) FileAccessCard()
            LastScanLabel(state.summary)

            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(state.detections) { detection ->
                    ResultCard(detection)
                }
            }
        }
    }
}

@Composable
private fun SummaryRow(state: ScanUiState) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceEvenly,
    ) {
        Stat(state.summary.malicious.toString(), stringResource(R.string.stat_malicious))
        Stat(state.summary.suspicious.toString(), stringResource(R.string.stat_suspicious))
        Stat(state.summary.clean.toString(), stringResource(R.string.stat_clean))
    }
}

@Composable
private fun Stat(value: String, label: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, fontSize = 28.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
        Text(label, fontSize = 12.sp)
    }
}

/**
 * Shown while the agent cannot read the download folder. Without this access
 * the download watcher stays idle, and the user would have no way of knowing
 * that a part of the protection they see announced is not actually running.
 */
@Composable
private fun FileAccessCard() {
    val context = LocalContext.current
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
        ),
    ) {
        Column(Modifier.padding(12.dp)) {
            Text(stringResource(R.string.file_access_title), fontWeight = FontWeight.Bold)
            Spacer(Modifier.padding(2.dp))
            Text(stringResource(R.string.file_access_body), fontSize = 12.sp)
            OutlinedButton(onClick = { context.startActivity(fileAccessIntent(context)) }) {
                Text(stringResource(R.string.file_access_action))
            }
        }
    }
}

/**
 * The all-files access screen on Android 11+, application details below it —
 * there is no single intent that covers both, and sending an unsupported one
 * would drop the user on an error.
 */
private fun fileAccessIntent(context: android.content.Context): Intent {
    val target = Uri.parse("package:" + context.packageName)
    val action = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION
    } else {
        Settings.ACTION_APPLICATION_DETAILS_SETTINGS
    }
    return Intent(action, target)
}

/** Date of the last completed scan, so the figures above are never ambiguous
 *  about whether they describe today or last month. */
@Composable
private fun LastScanLabel(summary: ScanSummary) {
    if (!summary.hasRun) return
    val stamp = remember(summary.at) {
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
            .format(Date(summary.at))
    }
    Text(
        stringResource(R.string.last_scan, stamp),
        fontSize = 12.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun ResultCard(detection: DetectionView) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                // The label can be a downloaded file name, far longer than an
                // application name: it takes the room that is left and is cut,
                // so the verdict beside it is never pushed off or run into.
                Text(
                    detection.label,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false),
                )
                Spacer(Modifier.padding(horizontal = 4.dp))
                Text("${detection.verdict.name} · ${detection.score}", maxLines = 1)
            }
            Text(detection.packageName, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            Spacer(Modifier.padding(2.dp))
            detection.reasons.take(3).forEach { reason ->
                Text("• $reason", fontSize = 12.sp)
            }
        }
    }
}
