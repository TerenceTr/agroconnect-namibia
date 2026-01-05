import React, { useEffect } from "react";
import { Card, CardHeader, CardContent, CardTitle } from "../../components/ui/Card";
import { useAiRecommend } from "../../hooks/ai/useAiRecommend";
import { Loader2, Sparkles } from "lucide-react";

export default function RecommendationList({
  buyerId = null,
  recent = [],
  limit = 5,
}) {
  const { getRecommendations, recommendations, loading, error } =
    useAiRecommend();

  useEffect(() => {
    getRecommendations({
      buyer_id: buyerId,
      recent_product_ids: recent,
      k: limit,
    });
  }, [buyerId, recent, limit]);

  return (
    <Card className="rounded-2xl shadow-md">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-primary" />
          Recommended Products
        </CardTitle>
      </CardHeader>

      <CardContent>
        {loading && (
          <div className="flex justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
          </div>
        )}

        {error && (
          <div className="text-red-600 text-sm py-4 text-center">{error}</div>
        )}

        {recommendations && (
          <ul className="space-y-3">
            {recommendations.recommendations.map((rec) => (
              <li
                key={rec.product_id}
                className="flex justify-between p-3 bg-gray-50 rounded-xl border"
              >
                <span className="font-medium">Product #{rec.product_id}</span>
                <span className="text-sm text-gray-500">
                  Score: {rec.score}
                </span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
