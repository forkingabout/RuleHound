package core

import "gopkg.in/yaml.v3"

func ParseYAML(data []byte) (*yaml.Node, error) {
	var root yaml.Node

	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}

	return &root, nil
}
