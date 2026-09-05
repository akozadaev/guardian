package queue

import (
	"context"
	"encoding/json"
	"time"

	"github.com/akozadaev/guardian/internal/models"
	"github.com/segmentio/kafka-go"
	"go.uber.org/zap"
)

// Publisher отправляет события асинхронно (в Kafka или без выполнения действий).
type Publisher interface {
	PublishRequestLog(ctx context.Context, log *models.RequestLog) error
	PublishAudit(ctx context.Context, log *models.AuditLog) error
	Close() error
}

// NopPublisher отбрасывает события.
type NopPublisher struct{}

func (NopPublisher) PublishRequestLog(context.Context, *models.RequestLog) error { return nil }
func (NopPublisher) PublishAudit(context.Context, *models.AuditLog) error        { return nil }
func (NopPublisher) Close() error                                                { return nil }

// KafkaPublisher использует segmentio/kafka-go с подтверждениями RequireAll.
type KafkaPublisher struct {
	writer *kafka.Writer
	log    *zap.Logger
}

func NewKafkaPublisher(brokers []string, topic string, log *zap.Logger) *KafkaPublisher {
	w := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Topic:        topic,
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireAll,
		Async:        true,
		BatchTimeout: 10 * time.Millisecond,
		BatchSize:    100,
	}
	return &KafkaPublisher{writer: w, log: log}
}

func (k *KafkaPublisher) PublishRequestLog(ctx context.Context, log *models.RequestLog) error {
	return k.publish(ctx, "request_log", log)
}

func (k *KafkaPublisher) PublishAudit(ctx context.Context, log *models.AuditLog) error {
	return k.publish(ctx, "audit", log)
}

func (k *KafkaPublisher) publish(ctx context.Context, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	err = k.writer.WriteMessages(ctx, kafka.Message{
		Key:   []byte(key),
		Value: raw,
		Time:  time.Now(),
	})
	if err != nil && k.log != nil {
		k.log.Warn("kafka publish failed", zap.Error(err))
	}
	return err
}

func (k *KafkaPublisher) Close() error {
	return k.writer.Close()
}

// NewPublisher выбирает бэкенд из конфигурации.
func NewPublisher(enabled bool, backend string, brokers []string, topic string, log *zap.Logger) Publisher {
	if !enabled || backend == "" || backend == "none" {
		return NopPublisher{}
	}
	if backend == "kafka" && len(brokers) > 0 {
		return NewKafkaPublisher(brokers, topic, log)
	}
	return NopPublisher{}
}
