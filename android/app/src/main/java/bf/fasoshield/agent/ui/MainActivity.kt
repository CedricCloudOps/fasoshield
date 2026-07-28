package bf.fasoshield.agent.ui

import android.Manifest
import android.os.Build
import android.os.Bundle
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
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
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
            ) {
                Text(detection.label, fontWeight = FontWeight.Bold)
                Text("${detection.verdict.name} · ${detection.score}")
            }
            Text(detection.packageName, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            Spacer(Modifier.padding(2.dp))
            detection.reasons.take(3).forEach { reason ->
                Text("• $reason", fontSize = 12.sp)
            }
        }
    }
}
