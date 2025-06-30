# .kilocode Directory

## 🎯 Purpose

This directory contains the **foundational rules, conventions, and cognitive frameworks** for the Universal Bitcoin project. These documents serve as the single source of truth for development standards, architectural decisions, and project guidelines.

## 📁 Structure

```
.kilocode/
├── README.md                    # This file - overview of the directory
├── rules/                       # Development rules and conventions
│   ├── MEMORY-MAP.md           # Cognitive framework and mental models
│   ├── CODE-CONVENTIONS.md     # Coding standards and style guide
│   ├── SECURITY-GUIDELINES.md  # Security requirements and best practices
│   ├── TESTING-STRATEGY.md     # Testing approaches and standards
│   └── DEPLOYMENT-GUIDE.md     # Deployment procedures and checklists
├── templates/                   # Code and documentation templates
│   ├── service-template.md     # Service implementation template
│   ├── api-endpoint-template.md # API endpoint template
│   └── test-template.md        # Test file template
└── workflows/                   # Development workflow documentation
    ├── DEVELOPMENT-WORKFLOW.md # Feature development process
    ├── CODE-REVIEW-PROCESS.md  # Code review guidelines
    └── RELEASE-PROCESS.md      # Release management procedures
```

## 🔧 How to Use

### For New Developers
1. **Start with [`MEMORY-MAP.md`](rules/MEMORY-MAP.md)** - Understand the mental models and cognitive framework
2. **Review [`CODE-CONVENTIONS.md`](rules/CODE-CONVENTIONS.md)** - Learn coding standards and style requirements
3. **Study [`SECURITY-GUIDELINES.md`](rules/SECURITY-GUIDELINES.md)** - Understand security requirements (mandatory)
4. **Follow [`DEVELOPMENT-WORKFLOW.md`](workflows/DEVELOPMENT-WORKFLOW.md)** - Learn the development process

### For Feature Development
1. **Architecture Phase**: Review [`MEMORY-MAP.md`](rules/MEMORY-MAP.md) for decision frameworks
2. **Implementation Phase**: Follow [`CODE-CONVENTIONS.md`](rules/CODE-CONVENTIONS.md) standards
3. **Security Phase**: Validate against [`SECURITY-GUIDELINES.md`](rules/SECURITY-GUIDELINES.md)
4. **Testing Phase**: Apply [`TESTING-STRATEGY.md`](rules/TESTING-STRATEGY.md) approaches
5. **Deployment Phase**: Use [`DEPLOYMENT-GUIDE.md`](rules/DEPLOYMENT-GUIDE.md) procedures

### For Code Reviews
- Use [`CODE-REVIEW-PROCESS.md`](workflows/CODE-REVIEW-PROCESS.md) as checklist
- Validate security compliance with [`SECURITY-GUIDELINES.md`](rules/SECURITY-GUIDELINES.md)
- Ensure code follows [`CODE-CONVENTIONS.md`](rules/CODE-CONVENTIONS.md) standards

## 🧠 Core Principles

### 1. **Security First**
Every decision must prioritize security, especially with Guardian Angels multi-sig operations and Bitcoin key management.

### 2. **Transparency by Design**
All operations must be auditable and verifiable by the public. No black boxes.

### 3. **Scalability Mindset**
Design for growth across multiple blockchains and high transaction volumes.

### 4. **Reliability Priority**
Financial systems require 99.9%+ uptime. Build for resilience.

## 📋 Compliance Requirements

### Mandatory Reading
- [ ] [`MEMORY-MAP.md`](rules/MEMORY-MAP.md) - Mental models and decision frameworks
- [ ] [`SECURITY-GUIDELINES.md`](rules/SECURITY-GUIDELINES.md) - Security requirements (non-negotiable)
- [ ] [`CODE-CONVENTIONS.md`](rules/CODE-CONVENTIONS.md) - Coding standards

### Before First Commit
- [ ] Understand Guardian Angels security model
- [ ] Know Bitcoin message signing requirements
- [ ] Familiar with multi-chain architecture patterns
- [ ] Aware of rate limiting and revenue preservation logic

### Before Each Feature
- [ ] Review relevant mental models in [`MEMORY-MAP.md`](rules/MEMORY-MAP.md)
- [ ] Plan according to [`DEVELOPMENT-WORKFLOW.md`](workflows/DEVELOPMENT-WORKFLOW.md)
- [ ] Design with security guidelines in mind

## 🔄 Maintenance

### Updating Rules
- Rules changes require team consensus
- Security guideline changes require security review
- All changes must be documented with rationale

### Version Control
- All `.kilocode` files are version controlled
- Changes trigger team notifications
- Breaking changes require migration guides

## 🎓 Learning Path

### Week 1: Foundation
- [ ] Read [`MEMORY-MAP.md`](rules/MEMORY-MAP.md) thoroughly
- [ ] Understand the three pillars: Transparency, Security, Scalability
- [ ] Grasp Guardian Angels security model
- [ ] Learn Bitcoin proof-of-reserves concepts

### Week 2: Implementation
- [ ] Master [`CODE-CONVENTIONS.md`](rules/CODE-CONVENTIONS.md)
- [ ] Study [`SECURITY-GUIDELINES.md`](rules/SECURITY-GUIDELINES.md)
- [ ] Practice with templates in [`templates/`](templates/)
- [ ] Follow [`DEVELOPMENT-WORKFLOW.md`](workflows/DEVELOPMENT-WORKFLOW.md)

### Week 3: Mastery
- [ ] Contribute to rule improvements
- [ ] Mentor new team members
- [ ] Lead code reviews
- [ ] Optimize development processes

## 🚨 Emergency Procedures

### Security Incident
1. **Immediate**: Follow [`SECURITY-GUIDELINES.md`](rules/SECURITY-GUIDELINES.md) incident response
2. **Escalation**: Alert Guardian Angels immediately
3. **Documentation**: Record all actions in audit logs

### System Failure
1. **Assessment**: Use [`DEPLOYMENT-GUIDE.md`](rules/DEPLOYMENT-GUIDE.md) diagnostic procedures
2. **Recovery**: Follow disaster recovery protocols
3. **Post-mortem**: Update procedures based on learnings

## 📞 Support

### Questions About Rules
- **Architecture**: Consult [`MEMORY-MAP.md`](rules/MEMORY-MAP.md) decision frameworks
- **Code Style**: Reference [`CODE-CONVENTIONS.md`](rules/CODE-CONVENTIONS.md) examples
- **Security**: Review [`SECURITY-GUIDELINES.md`](rules/SECURITY-GUIDELINES.md) requirements

### Rule Conflicts
- Security guidelines always take precedence
- Consult team lead for clarification
- Document exceptions with rationale

---

**Remember: These rules exist to ensure consistency, security, and scalability. When in doubt, prioritize security first, transparency second, and user experience third.**