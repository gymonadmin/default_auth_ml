// src/entities/profile.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToOne,
  JoinColumn,
  Index,
} from 'typeorm';

@Entity('profiles')
@Index('profiles_user_id_unique', ['userId'], { unique: true })
export class Profile {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ 
    type: 'uuid', 
    nullable: false 
  })
  userId!: string;

  @Column({ 
    type: 'varchar', 
    length: 50, 
    nullable: false 
  })
  firstName!: string;

  @Column({ 
    type: 'varchar', 
    length: 50, 
    nullable: false 
  })
  lastName!: string;

  @CreateDateColumn({ 
    type: 'timestamptz',
    default: () => 'CURRENT_TIMESTAMP'
  })
  createdAt!: Date;

  @UpdateDateColumn({ 
    type: 'timestamptz',
    default: () => 'CURRENT_TIMESTAMP'
  })
  updatedAt!: Date;

  // Relationships - using string name to avoid circular imports
  @OneToOne('User', 'profile', {
    onDelete: 'CASCADE'
  })
  @JoinColumn({ 
    name: 'userId',
    foreignKeyConstraintName: 'fk_profiles_user'
  })
  user!: any;

  // Computed properties
  get fullName(): string {
    return `${this.firstName} ${this.lastName}`.trim();
  }

  get initials(): string {
    const firstInitial = this.firstName.charAt(0).toUpperCase();
    const lastInitial = this.lastName.charAt(0).toUpperCase();
    return `${firstInitial}${lastInitial}`;
  }

  // Methods
  updateName(firstName: string, lastName: string): void {
    this.firstName = firstName.trim();
    this.lastName = lastName.trim();
  }
}
