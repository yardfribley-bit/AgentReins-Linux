import { BarChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import * as echarts from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { useEffect, useRef } from 'react'
import type { TimelineBucket } from './types'

echarts.use([BarChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer])

export function TimelineChart({ buckets, onPick }: { buckets: TimelineBucket[]; onPick: (bucket: TimelineBucket, layer: 'D' | 'B') => void }) {
  const ref = useRef<HTMLDivElement>(null)
  const pick = useRef(onPick)
  pick.current = onPick

  useEffect(() => {
    const node = ref.current
    if (!node) return
    const chart = echarts.init(node, undefined, { renderer: 'canvas' })
    chart.setOption({
      backgroundColor: 'transparent',
      legend: { top: 0, right: 0, textStyle: { color: '#93a4b8', fontSize: 12 }, itemWidth: 10, itemHeight: 10 },
      grid: { left: 36, right: 8, top: 32, bottom: 24 },
      tooltip: { trigger: 'axis' },
      xAxis: { type: 'category', data: buckets.map((bucket) => bucket.label), axisLabel: { color: '#6d8096' }, axisLine: { lineStyle: { color: '#243140' } } },
      yAxis: { type: 'value', minInterval: 1, axisLabel: { color: '#6d8096' }, splitLine: { lineStyle: { color: '#1c2836' } } },
      series: [
        { name: '决策层', type: 'bar', stack: 'alerts', data: buckets.map((bucket) => bucket.decision), itemStyle: { color: '#8eb6ff' }, barMaxWidth: 28 },
        { name: '行为层', type: 'bar', stack: 'alerts', data: buckets.map((bucket) => bucket.behavior), itemStyle: { color: '#63d2c4' }, barMaxWidth: 28 },
      ],
    })
    chart.on('click', (params) => {
      const bucket = buckets[params.dataIndex ?? -1]
      if (!bucket) return
      pick.current(bucket, params.seriesName === '行为层' ? 'B' : 'D')
    })
    const observer = new ResizeObserver(() => chart.resize())
    observer.observe(node)
    return () => {
      observer.disconnect()
      chart.dispose()
    }
  }, [buckets])

  return <div ref={ref} className="h-52 w-full" />
}
