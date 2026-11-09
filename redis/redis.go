// Package sitegooseredis times the Redis commands go-redis v9 runs, for
// Server speed -> Queries, through go-redis's own hooks:
//
//	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379"})
//	rdb.AddHook(sitegooseredis.Hook(p))
//
// *redis.Client, *redis.ClusterClient, *redis.Ring and a
// redis.UniversalClient all take it. Each command is counted as database
// "redis" with only its name, a subcommand and its first key's shape kept
// ("GET user:?:cart"), never a value; blocking commands (BLPOP, XREAD
// BLOCK...) aren't counted, as they wait rather than work. A pipeline is one
// call for its whole round trip ("PIPELINE GET user:?"), a TxPipeline
// "MULTI ...". A nil reply (redis.Nil) is an answer, not a failure, as is a
// transaction WATCH called off (redis.TxFailedErr); an error reply or no
// answer is one. A command counts under the request its ctx belongs to
// (rdb.Get(r.Context(), ...)), else as a background query.
//
// The hook only times: the command, its answer and its error are the
// client's, untouched. It is in a module of its own so the platform package
// needs nothing but the standard library.
package sitegooseredis

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	sitegoose "github.com/sitegoose/sitegoose-go"
)

type hook struct{ p *sitegoose.Platform }

var _ redis.Hook = hook{}

// Hook is a go-redis hook timing commands on p: client.AddHook(Hook(p)).
func Hook(p *sitegoose.Platform) redis.Hook { return hook{p: p} }

func (hook) DialHook(next redis.DialHook) redis.DialHook { return next }

func (h hook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		started := time.Now()
		err := next(ctx, cmd)
		h.command(ctx, cmd, time.Since(started), err)
		return err
	}
}

func (h hook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		started := time.Now()
		err := next(ctx, cmds)
		h.pipeline(ctx, cmds, time.Since(started), err)
		return err
	}
}

// failure is err unless it is a nil reply or a transaction WATCH called off:
// neither is an error reply or a lost answer.
func failure(err error) error {
	if err == nil || errors.Is(err, redis.Nil) || errors.Is(err, redis.TxFailedErr) {
		return nil
	}
	return err
}

func (h hook) command(ctx context.Context, cmd redis.Cmder, d time.Duration, err error) {
	if h.p == nil || cmd == nil {
		return
	}
	defer func() { recover() }() // never into the app
	if err == nil {
		err = cmd.Err()
	}
	h.p.RecordRedis(ctx, cmd.Args(), d, failure(err))
}

func (h hook) pipeline(ctx context.Context, cmds []redis.Cmder, d time.Duration, err error) {
	if h.p == nil || len(cmds) == 0 {
		return
	}
	defer func() { recover() }() // never into the app
	err = failure(err)
	args := make([][]any, 0, len(cmds))
	for _, cmd := range cmds {
		if cmd == nil {
			continue
		}
		if err == nil {
			err = failure(cmd.Err())
		}
		args = append(args, cmd.Args())
	}
	// A TxPipeline's commands come wrapped in MULTI ... EXEC.
	transaction := cmds[0] != nil && cmds[0].Name() == "multi"
	h.p.RecordRedisPipeline(ctx, args, transaction, d, err)
}
