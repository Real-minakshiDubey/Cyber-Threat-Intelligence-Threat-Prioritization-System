import pandas as pd

def prepare_dataframe(history):
    df = pd.DataFrame(history)

    if df.empty:
        return df

    df["score"] = pd.to_numeric(df["score"])
    return df


def get_summary_stats(df):
    return {
        "avg_score": df["score"].mean(),
        "max_score": df["score"].max(),
        "min_score": df["score"].min(),
        "total_scans": len(df)
    }


def get_top_risky(df, n=5):
    return df.sort_values(by="score", ascending=False).head(n)


def get_ip_risk(df):
    return df.groupby("ip")["score"].mean().reset_index()


def get_distribution(df):
    return df["level"].value_counts().to_dict()