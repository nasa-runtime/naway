//! 响应变换的当前实际处理量与成功完成集合收益。

use super::model::Point;
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct View {
    availability: &'static str,
    encode_input_bytes_per_second: Option<f64>,
    encode_output_bytes_per_second: Option<f64>,
    decode_input_bytes_per_second: Option<f64>,
    decode_output_bytes_per_second: Option<f64>,
    encode_inflight: Option<f64>,
    decode_inflight: Option<f64>,
    completed_encode_per_second: Option<f64>,
    completed_encode_input_bytes_per_second: Option<f64>,
    completed_encode_output_bytes_per_second: Option<f64>,
    completed_encode_saved_bytes_per_second: Option<f64>,
    completed_encode_savings_ratio: Option<f64>,
}

/// 业务作用：从完整固定目录汇总响应codec处理量，收益只使用成功完成变换的成对字节。
///
/// 参数说明：
/// - `points`：当前节点或集群实际区间的有限指标与覆盖。
///
/// 返回：当前处理速率及活动量；完整覆盖且完成区间有效时提供可为负的成功编码收益。
pub(super) fn view(points: &[Point<'_>]) -> View {
    let selected: Vec<_> = points
        .iter()
        .filter(|point| {
            crate::observability::response_codec::DESCRIPTORS
                .iter()
                .any(|descriptor| descriptor.name == point.name)
        })
        .collect();
    let find = |name, operation, algorithm, extra: Option<(&str, &str)>| {
        selected
            .iter()
            .find(|point| {
                point.name == name
                    && point.labels.len() == 2 + usize::from(extra.is_some())
                    && point
                        .labels
                        .get("operation")
                        .is_some_and(|value| value == operation)
                    && point
                        .labels
                        .get("algorithm")
                        .is_some_and(|value| value == algorithm)
                    && extra.is_none_or(|(key, expected)| {
                        point.labels.get(key).is_some_and(|value| value == expected)
                    })
            })
            .copied()
    };
    let sum = |name, operation, extra, gauge: bool| {
        ["gzip", "br"].into_iter().try_fold(0.0, |sum, algorithm| {
            let point = find(name, operation, algorithm, extra)?;
            Some(
                sum + if gauge {
                    point.current?
                } else {
                    point.per_second?
                },
            )
        })
    };
    let complete = selected.len() == 32
        && selected
            .iter()
            .all(|point| point.availability == "available");
    let mut result = View {
        availability: if complete {
            "available"
        } else if selected
            .iter()
            .any(|point| point.current.is_some() || point.per_second.is_some())
        {
            "partial"
        } else {
            "unknown"
        },
        encode_input_bytes_per_second: sum(
            "gw_response_codec_bytes_total",
            "encode",
            Some(("side", "input")),
            false,
        ),
        encode_output_bytes_per_second: sum(
            "gw_response_codec_bytes_total",
            "encode",
            Some(("side", "output")),
            false,
        ),
        decode_input_bytes_per_second: sum(
            "gw_response_codec_bytes_total",
            "decode",
            Some(("side", "input")),
            false,
        ),
        decode_output_bytes_per_second: sum(
            "gw_response_codec_bytes_total",
            "decode",
            Some(("side", "output")),
            false,
        ),
        encode_inflight: sum("gw_response_codec_inflight", "encode", None, true),
        decode_inflight: sum("gw_response_codec_inflight", "decode", None, true),
        completed_encode_per_second: sum(
            "gw_response_codec_events_total",
            "encode",
            Some(("outcome", "eof")),
            false,
        ),
        completed_encode_input_bytes_per_second: sum(
            "gw_response_codec_completed_input_bytes_total",
            "encode",
            None,
            false,
        ),
        completed_encode_output_bytes_per_second: sum(
            "gw_response_codec_completed_output_bytes_total",
            "encode",
            None,
            false,
        ),
        completed_encode_saved_bytes_per_second: None,
        completed_encode_savings_ratio: None,
    };
    // 不同节点子集的输入输出不能相除；旧节点缺少新系列时保持原始部分量和未知收益。
    if !complete {
        return result;
    }
    for algorithm in ["gzip", "br"] {
        let values = (
            find(
                "gw_response_codec_events_total",
                "encode",
                algorithm,
                Some(("outcome", "eof")),
            )
            .and_then(|point| point.per_second),
            find(
                "gw_response_codec_completed_input_bytes_total",
                "encode",
                algorithm,
                None,
            )
            .and_then(|point| point.per_second),
            find(
                "gw_response_codec_completed_output_bytes_total",
                "encode",
                algorithm,
                None,
            )
            .and_then(|point| point.per_second),
        );
        let (Some(count), Some(input), Some(output)) = values else {
            return result;
        };
        if count == 0.0 && (input != 0.0 || output != 0.0) {
            result.availability = "inconsistent";
            return result;
        }
    }
    if let Some((input, output)) = result
        .completed_encode_input_bytes_per_second
        .zip(result.completed_encode_output_bytes_per_second)
        .filter(|(input, _)| *input > 0.0)
    {
        result.completed_encode_saved_bytes_per_second = Some(input - output);
        result.completed_encode_savings_ratio = Some((input - output) / input);
    }
    result
}
