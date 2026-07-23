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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import bf.fasoshield.agent.R
import bf.fasoshield.agent.scan.ScanResult
import bf.fasoshield.agent.scan.Verdict

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

            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(state.results.filter { it.verdict != Verdict.CLEAN }) { result ->
                    ResultCard(result)
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
        Stat(state.malicious.toString(), stringResource(R.string.stat_malicious))
        Stat(state.suspicious.toString(), stringResource(R.string.stat_suspicious))
        Stat(state.clean.toString(), stringResource(R.string.stat_clean))
    }
}

@Composable
private fun Stat(value: String, label: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, fontSize = 28.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace)
        Text(label, fontSize = 12.sp)
    }
}

@Composable
private fun ResultCard(result: ScanResult) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(result.facts.label, fontWeight = FontWeight.Bold)
                Text("${result.verdict.name} · ${result.score}")
            }
            Text(result.facts.packageName, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            Spacer(Modifier.padding(2.dp))
            result.findings.take(3).forEach { finding ->
                Text("• ${finding.title}", fontSize = 12.sp)
            }
        }
    }
}
