# Moshi / Retrofit reflection-based adapters
-keep class bf.fasoshield.agent.network.** { *; }
-keepclassmembers class bf.fasoshield.agent.network.** { *; }
-keep @com.squareup.moshi.JsonClass class * { *; }

# Room entities
-keep class bf.fasoshield.agent.data.*Entry { *; }
