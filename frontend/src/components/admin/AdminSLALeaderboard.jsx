// ============================================================================
// AdminSLALeaderboard.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Displays per-admin moderation SLA performance
// ============================================================================

export default function AdminSLALeaderboard({ data }) {
  if (!data?.length) {
    return <div className="empty">No SLA data available</div>;
  }

  return (
    <div className="card">
      <h3>Admin SLA Leaderboard (Monthly)</h3>

      <table className="table">
        <thead>
          <tr>
            <th>Admin</th>
            <th>Reviewed</th>
            <th>Breaches</th>
            <th>Avg Hours</th>
            <th>SLA Score</th>
          </tr>
        </thead>
        <tbody>
          {data.map((a, i) => (
            <tr key={a.admin_id}>
              <td>
                {i === 0 && "🏆 "}
                {a.admin_name}
              </td>
              <td>{a.reviewed_count}</td>
              <td className={a.breached_count > 0 ? "danger" : ""}>
                {a.breached_count}
              </td>
              <td>{a.avg_review_hours}h</td>
              <td>
                <strong>{a.sla_score}%</strong>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
