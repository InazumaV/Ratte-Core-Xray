package main

import "errors"

func TypeTrans[t any](p any) (p2 t, err error) {
	if p, ok := p.(t); !ok {
		return p2, errors.New("the type is invalid")
	} else {
		return p, nil
	}
}
