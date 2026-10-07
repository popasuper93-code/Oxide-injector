package com.oxide.injector;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity {

    static {
        System.loadLibrary("injector");
    }

    // Нативные функции
    public native boolean injectCheat(String processName, String soPath);

    private TextView statusText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(30, 30, 30, 30);

        TextView title = new TextView(this);
        title.setText("OXIDE INJECTOR");
        title.setTextSize(22);
        layout.addView(title);

        statusText = new TextView(this);
        statusText.setText("Статус: ожидание");
        statusText.setTextSize(14);
        layout.addView(statusText);

        Button injectBtn = new Button(this);
        injectBtn.setText("ИНЖЕКТИТЬ ЧИТ");
        injectBtn.setOnClickListener(v -> {
            new Thread(() -> {
                String soPath = getFilesDir().getAbsolutePath() + "/libcheat.so";
                boolean result = injectCheat("com.oxide.game", soPath);
                new Handler(Looper.getMainLooper()).post(() -> {
                    if (result) {
                        statusText.setText("✅ Чит загружен!");
                        Toast.makeText(this, "Чит успешно внедрён!", Toast.LENGTH_LONG).show();
                    } else {
                        statusText.setText("❌ Ошибка инжекта");
                        Toast.makeText(this, "Не удалось внедрить чит", Toast.LENGTH_LONG).show();
                    }
                });
            }).start();
        });
        layout.addView(injectBtn);

        setContentView(layout);
    }
}
