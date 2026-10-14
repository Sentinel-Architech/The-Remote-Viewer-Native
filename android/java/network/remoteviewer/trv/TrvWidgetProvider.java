package network.remoteviewer.trv;

import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.widget.RemoteViews;

/**
 * TRV home-screen widget.
 *
 * <p>Today: build progress for The Remote Viewer Network (items done /
 * items next / tests passing). Designed to EVOLVE into the founder's
 * network-health dashboard: {@link TrvWidgetData#snapshot()} will stop
 * returning the hardcoded build snapshot and start returning live
 * health / trends / topics rows. The provider, layout, and update path
 * below do not change — only the data source does.
 *
 * <p>Registered in AndroidManifest.xml as a {@code receiver} with the
 * {@code APPWIDGET_UPDATE} action and {@code trv_widget_info.xml}.
 */
public class TrvWidgetProvider extends AppWidgetProvider {

    @Override
    public void onUpdate(Context context, AppWidgetManager appWidgetManager,
                         int[] appWidgetIds) {
        TrvWidgetData.Snapshot s = TrvWidgetData.snapshot(context);
        for (int appWidgetId : appWidgetIds) {
            updateWidget(context, appWidgetManager, appWidgetId, s);
        }
    }

    /**
     * Push one snapshot into one widget instance. The app itself can call
     * this any time fresh data lands (build finished, health tick) via
     * AppWidgetManager — that is the live-update path the dashboard will
     * use instead of relying on updatePeriodMillis.
     */
    public static void updateWidget(Context context,
                                    AppWidgetManager appWidgetManager,
                                    int appWidgetId,
                                    TrvWidgetData.Snapshot s) {
        RemoteViews views =
                new RemoteViews(context.getPackageName(), R.layout.trv_widget);
        views.setTextViewText(R.id.widget_title, s.title);
        views.setTextViewText(R.id.widget_headline, s.headline);
        views.setTextViewText(R.id.widget_row1, s.row1);
        views.setTextViewText(R.id.widget_row2, s.row2);
        views.setTextViewText(R.id.widget_row3, s.row3);
        views.setProgressBar(R.id.widget_progress, 100,
                Math.round(s.progress * 100f), false);
        appWidgetManager.updateAppWidget(appWidgetId, views);
    }
}
