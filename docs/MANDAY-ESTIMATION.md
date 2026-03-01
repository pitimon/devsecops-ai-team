# Man-Day Estimation — DevSecOps AI Team Plugin

## Work Breakdown Structure

| Phase        | Task                             | Estimated Days |
| ------------ | -------------------------------- | -------------- |
| **Phase 1**  | Foundation (skeleton, docs, git) | 2              |
| **Phase 2**  | Sidecar Runner + 2 tools         | 3              |
| **Phase 3**  | 5 remaining tools + references   | 4              |
| **Phase 4**  | 7 agents + 4 skills              | 3              |
| **Phase 4b** | 11 agents                        | 2              |
| **Phase 5**  | Hooks + templates + hardening    | 3              |
| **Phase 6**  | CI/CD + testing + release        | 3              |
| **Total**    |                                  | **20 days**    |

## Assumptions

- Solo developer with DevSecOps experience
- Docker and security tool familiarity
- Claude Code plugin development experience
- All tools have existing Docker images

## Risk Factors

| Risk                      | Impact | Mitigation                            |
| ------------------------- | ------ | ------------------------------------- |
| Tool API changes          | Medium | Pin image versions, test fixtures     |
| Docker compatibility      | Low    | Multi-platform builds                 |
| Framework version updates | Low    | frameworks.json tracking              |
| Large codebase scanning   | Medium | Timeout configs, incremental scanning |
